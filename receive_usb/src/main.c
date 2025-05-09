#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/storage/flash_map.h>
#include <string.h>
#include <stdint.h>

//REMEMBER TO CHANGE THE COM IN THE SENDER TOO
#define UART_NODE DT_NODELABEL(usart1) // usart1 if attaching a new USB in the pins, yellow to D8 and orange to D2 (using COM different to COM3) or usart2 if using COM3 (in this case not possible to debug at the same time)
#define RX_BUF_SIZE 2048

#define STORAGE_PARTITION     storage_partition

LOG_MODULE_REGISTER(uart_receiver, LOG_LEVEL_INF);

static const struct device *uart_dev;

#pragma pack(push, 1)
struct participant_data {
    uint32_t receiver_index;
    uint8_t secret_share[32];
    uint8_t public_key[64];
    uint8_t group_public_key[33];
    uint32_t key_index;
    uint32_t max_participants;
};
#pragma pack(pop)

// FIFO queue for received data
K_FIFO_DEFINE(uart_fifo);

// Struct to hold received data before adding to FIFO
struct uart_fifo_item {
    void *fifo_reserved;  // Required by Zephyr FIFO
    struct participant_data data;
};

/* UART Callback for Handling Received Data */
void uart_cb(const struct device *dev, void *user_data)
{
    static uint8_t rx_buf[sizeof(struct participant_data)];
    static size_t rx_pos = 0;

    while (uart_irq_update(dev) && uart_irq_rx_ready(dev)) {
        uint8_t byte;
        int recv_len = uart_fifo_read(dev, &byte, 1);

        if (recv_len > 0) {
            rx_buf[rx_pos++] = byte;

            // Check if we have received a full struct
            if (rx_pos == sizeof(struct participant_data)) {
                struct uart_fifo_item *item = k_malloc(sizeof(struct uart_fifo_item));
                if (item) {
                    memcpy(&item->data, rx_buf, sizeof(struct participant_data));
                    k_fifo_put(&uart_fifo, item);  // Push to FIFO
                }
                rx_pos = 0;  // Reset buffer position
            }
        }
    }
}

/* Processing Thread */
void uart_processing_thread(void)
{
    while (1) {
        struct uart_fifo_item *item = k_fifo_get(&uart_fifo, K_FOREVER);
        if (item) {
            struct participant_data *received_data = &item->data;

            // Print the received data
            LOG_INF("\n=== Received Data ===");
            LOG_INF("Receiver Index: %d", received_data->receiver_index);
            LOG_INF("Key Index: %d", received_data->key_index);
            LOG_INF("Max Participants: %d", received_data->max_participants);

            char hex_buf[129]; // Enough for 64-byte keys + null terminator

            // Convert Secret Share to hex
            for (int i = 0; i < 32; i++) {
                sprintf(&hex_buf[i * 2], "%02x", received_data->secret_share[i]);
            }
            hex_buf[64] = '\0';  // Null-terminate the string
            LOG_INF("Secret Share: %s", hex_buf);

            // Convert Group Public Key to hex
            for (int i = 0; i < 33; i++) {
                sprintf(&hex_buf[i * 2], "%02x", received_data->group_public_key[i]);
            }
            hex_buf[66] = '\0';
            LOG_INF("Group Public Key: %s", hex_buf);

            // Convert Public Key to hex
            for (int i = 0; i < 64; i++) {
                sprintf(&hex_buf[i * 2], "%02x", received_data->public_key[i]);
            }
            hex_buf[128] = '\0';
            LOG_INF("Public Key: %s", hex_buf);

            const struct flash_area *fa;
            int rc = flash_area_open(FIXED_PARTITION_ID(STORAGE_PARTITION), &fa);
            if (rc < 0) {
                LOG_ERR("Failed to open flash area (%d)", rc);
                return;
            }

            // Erase sector(s)
            const struct device *flash_dev = flash_area_get_device(fa);
            if (!device_is_ready(flash_dev)) {
                LOG_ERR("Flash device not ready");
                flash_area_close(fa);
                return;
            }

            // Use flash_get_page_info_by_offs() to get erase block size
            struct flash_pages_info info;
            rc = flash_get_page_info_by_offs(flash_dev, fa->fa_off, &info);
            if (rc != 0) {
                LOG_ERR("Failed to get flash page info (%d)", rc);
                flash_area_close(fa);
                return;
            }

            size_t erase_size = info.size;
            size_t aligned_erase_size = ROUND_UP(sizeof(struct participant_data), erase_size);

            // Erase flash area at offset 0, aligned to erase block
            rc = flash_area_erase(fa, 0, aligned_erase_size);
            if (rc != 0) {
                LOG_ERR("Failed to erase flash (%d)", rc);
                flash_area_close(fa);
                return;
            }

            // Write data
            size_t write_block_size = flash_get_write_block_size(flash_dev);
            size_t padded_size = ROUND_UP(sizeof(struct participant_data), write_block_size);

            uint8_t padded_buf[padded_size];
            memset(padded_buf, 0xFF, padded_size);
            memcpy(padded_buf, received_data, sizeof(struct participant_data));

            rc = flash_area_write(fa, 0, padded_buf, padded_size);

            if (rc != 0) {
                LOG_ERR("Failed to write to flash (%d)", rc);
                flash_area_close(fa);
                return;
            }

            LOG_INF("Data written to flash.");

            struct participant_data read_back;
            rc = flash_area_read(fa, 0, &read_back, sizeof(struct participant_data));
            if (rc != 0) {
                LOG_ERR("Failed to read back data from flash (%d)", rc);
            } else if (memcmp(&read_back, received_data, sizeof(struct participant_data)) == 0) {
                LOG_INF("Flash verification succeeded.");
            } else {
                LOG_ERR("Flash verification failed: data mismatch.");
            }

            flash_area_close(fa);

            k_free(item);  // Free allocated memory
        }
    }
}

K_THREAD_DEFINE(uart_thread_id, 4096, uart_processing_thread, NULL, NULL, NULL, 5, 0, 0);

void main(void)
{
    printk("=== STM32 Zephyr UART Receiver ===\n");

    uart_dev = DEVICE_DT_GET(UART_NODE);
    if (!device_is_ready(uart_dev)) {
        printk("UART device not ready\n");
        return;
    }

    struct uart_config uart_cfg = {
        .baudrate = 115200,
        .parity = UART_CFG_PARITY_NONE,
        .stop_bits = UART_CFG_STOP_BITS_1,
        .data_bits = UART_CFG_DATA_BITS_8,
        .flow_ctrl = UART_CFG_FLOW_CTRL_NONE,
    };

    int ret = uart_configure(uart_dev, &uart_cfg);
    if (ret != 0) {
        printk("Failed to configure UART: %d\n", ret);
        return;
    }

    uart_irq_callback_set(uart_dev, uart_cb);
    uart_irq_rx_enable(uart_dev);

    printk("UART receiver initialized. Waiting for data...\n");

    const struct flash_area *fa;
    int rc = flash_area_open(FIXED_PARTITION_ID(STORAGE_PARTITION), &fa);
    if (rc != 0) {
        printk("Failed to open flash area (%d)\n", rc);
        return;
    }

    const struct device *flash_dev = flash_area_get_device(fa);
    if (!device_is_ready(flash_dev)) {
        printk("Flash device not ready\n");
        flash_area_close(fa);
        return;
    }

    // Read back stored data
    struct participant_data flash_data;
    rc = flash_area_read(fa, 0, &flash_data, sizeof(struct participant_data));
    if (rc != 0) {
        printk("Failed to read flash: %d\n", rc);
    } else {
        printk("=== Flash Content ===\n");
        printk("Receiver Index: %d\n", flash_data.receiver_index);
        printk("Key Index: %d\n", flash_data.key_index);
        printk("Max Participants: %d\n", flash_data.max_participants);

        char hex_buf[129];

        for (int i = 0; i < 32; i++) {
            sprintf(&hex_buf[i * 2], "%02x", flash_data.secret_share[i]);
        }
        hex_buf[64] = '\0';
        printk("Secret Share: %s\n", hex_buf);

        for (int i = 0; i < 33; i++) {
            sprintf(&hex_buf[i * 2], "%02x", flash_data.group_public_key[i]);
        }
        hex_buf[66] = '\0';
        printk("Group Public Key: %s\n", hex_buf);

        for (int i = 0; i < 64; i++) {
            sprintf(&hex_buf[i * 2], "%02x", flash_data.public_key[i]);
        }
        hex_buf[128] = '\0';
        printk("Public Key: %s\n", hex_buf);
    }

    flash_area_close(fa);

}
