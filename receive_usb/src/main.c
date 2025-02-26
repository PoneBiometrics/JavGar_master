#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/sys/printk.h>
#include <string.h>
#include <stdint.h>

#define UART_NODE DT_NODELABEL(usart2)
#define RX_BUF_SIZE 256             // Buffer size for receiving data

static const struct device *uart_dev;
static uint8_t rx_buf[RX_BUF_SIZE];
static volatile size_t rx_pos = 0;

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

/* UART Callback for Handling Received Data */
void uart_cb(const struct device *dev, void *user_data)
{
    while (uart_irq_update(dev) && uart_irq_rx_ready(dev)) {
        uint8_t byte;
        int recv_len = uart_fifo_read(dev, &byte, 1);

        if (recv_len > 0 && rx_pos < RX_BUF_SIZE) {
            rx_buf[rx_pos++] = byte;

            // Check if we received a full struct
            if (rx_pos == sizeof(struct participant_data)) {
                struct participant_data received_data;
                memcpy(&received_data, rx_buf, sizeof(received_data));

                // Print the received data
                printk("\n=== Received Data ===\n");
                printk("Receiver Index: %d\n", received_data.receiver_index);
                printk("Key Index: %d\n", received_data.key_index);
                printk("Max Participants: %d\n", received_data.max_participants);

                // Print hex values
                printk("Secret Share: ");
                for (int i = 0; i < 32; i++) {
                    printk("%02x", received_data.secret_share[i]);
                }
                printk("\n");

                printk("Public Key: ");
                for (int i = 0; i < 64; i++) {
                    printk("%02x", received_data.public_key[i]);
                }
                printk("\n");

                printk("Group Public Key: ");
                for (int i = 0; i < 33; i++) {
                    printk("%02x", received_data.group_public_key[i]);
                }
                printk("\n");

                // Reset buffer position
                rx_pos = 0;
            }
        }
    }
}

void main(void)
{   
    printk("=== STM32 Zephyr UART Receiver ===\n");

    /* Get UART device */
    const struct device *uart_dev = DEVICE_DT_GET(UART_NODE);

    if (!device_is_ready(uart_dev)) {
        printk("UART device not ready\n");
        return;
    }

    /* Configure UART */
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

    /* Enable UART Interrupt */
    uart_irq_callback_set(uart_dev, uart_cb);
    uart_irq_rx_enable(uart_dev);

    printk("UART receiver initialized. Waiting for data...\n");

    /* Keep the thread alive */
    while (1) {
        k_sleep(K_FOREVER);
    }
}