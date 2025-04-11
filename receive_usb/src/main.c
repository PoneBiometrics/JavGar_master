#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>
#include <zephyr/logging/log.h>
#include <string.h>
#include <stdint.h>

#define UART_NODE DT_NODELABEL(lpuart1) // usart1 if using COM6 when attaching a new USB in the pins or usart2 if using COM3 (in this case not possible to debug at the same time)
#define RX_BUF_SIZE 2048

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
}
