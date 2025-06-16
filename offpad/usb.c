#include "usb.h"
#include "usb_module.h"
#include "worker.h"

#include <zephyr/device.h>
#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/usb/usb_device.h>
/* usb_hid must be included after usb_device. Fixed in v3.6.0 */
#include <zephyr/usb/class/usb_hid.h>

LOG_MODULE_REGISTER(usb, CONFIG_COMMUNICATION_LOG_LEVEL);

#define BLOCK_SIZE      (64)
#define QUEUE_ITEM_SIZE (20)

K_MSGQ_DEFINE(usbSendQueue, BLOCK_SIZE, QUEUE_ITEM_SIZE, 4);

K_MUTEX_DEFINE(workerRunningMutex);

/**
 * @brief Define HID Usage Page item of size two.
 *
 * @param page Usage Page
 * @return     HID Usage Page item
 */
#define HID_USAGE_PAGE2(page) HID_ITEM(HID_ITEM_TAG_USAGE_PAGE, HID_ITEM_TYPE_GLOBAL, 2), page

#define HID_FIDO_USAGE_PAGE     0xD0, 0xF1
#define HID_FIDO_USAGE_CTAPHID  0x01
#define HID_FIDO_USAGE_DATA_IN  0x20
#define HID_FIDO_USAGE_DATA_OUT 0x21
#define HID_FIDO_REPORT_COUNT   0x40
/*
 * HID Report Descriptor
 * Report ID is present for completeness, although it can be omitted.
 * "usbhid-dump -d f1d0:f1d0 -e descriptor"
 */
static const uint8_t hid_report_desc[] = {
    HID_USAGE_PAGE2(HID_FIDO_USAGE_PAGE),
    HID_USAGE(HID_FIDO_USAGE_CTAPHID),
    HID_COLLECTION(HID_COLLECTION_APPLICATION),
    HID_USAGE(HID_FIDO_USAGE_DATA_IN),
    HID_LOGICAL_MIN8(0x00),
    HID_LOGICAL_MAX16(0xFF, 0x00),
    HID_REPORT_SIZE(8),
    HID_REPORT_COUNT(HID_FIDO_REPORT_COUNT),
    /* HID_INPUT (Data,Var,Abs) */
    HID_INPUT(0x02),
    HID_USAGE(HID_FIDO_USAGE_DATA_OUT),
    HID_LOGICAL_MIN8(0x00),
    HID_LOGICAL_MAX16(0xFF, 0x00),
    HID_REPORT_SIZE(8),
    HID_REPORT_COUNT(HID_FIDO_REPORT_COUNT),
    /* HID_INPUT (Data,Var,Abs) */
    HID_OUTPUT(0x02),
    HID_END_COLLECTION,
};

struct usb_dev_t {
    const struct device *dev;
    h_usb_callbacks_t callbacks;
    void *callbackData;
    struct k_work sendWorker;
    bool workerRunning;
    bool configured;
};

usb_dev_t usb_device;

/**
 * @brief Worker thread function
 *
 * @param work Pointer to worker object
 *
 * This function will "work" until the send queue is empty.
 * When empty it will return and end the work thread.
 */
static void sendUsbWorker(struct k_work *work)
{
    int res = 0;
    uint8_t message[BLOCK_SIZE];
    usb_dev_t *dev = CONTAINER_OF(work, usb_dev_t, sendWorker);
    if (dev == NULL) {
        LOG_ERR("no device for usb!!!");
        return;
    }
    memset(message, 0, sizeof(message));
    k_mutex_lock(&workerRunningMutex, K_FOREVER);
    res = k_msgq_peek(&usbSendQueue, &message);
    if (res != 0) {
        dev->workerRunning = false;
        k_mutex_unlock(&workerRunningMutex);
        return;
    }
    k_mutex_unlock(&workerRunningMutex);

    int bytes_written;
    res = k_msgq_get(&usbSendQueue, &message, K_NO_WAIT);
    if (res != 0) {
        LOG_ERR("usb send queue should not be empty %u", res);
        return;
    }
    hid_int_ep_write(usb_device.dev, message, sizeof(message), &bytes_written);
}

/**
 * @brief Starts a worker thread (if not already started)
 *
 * @param dev Pointer to dev object to use
 */
static void startWorker(usb_dev_t *dev)
{
    k_mutex_lock(&workerRunningMutex, K_FOREVER);
    if (!dev->workerRunning) {
        dev->workerRunning = true;
        worker_submit(&dev->sendWorker);
    }
    k_mutex_unlock(&workerRunningMutex);
}

/**
 * @brief HID read callback
 *
 * @param dev USB dev pointer
 *
 * This function is called by Zephyr when we have new incoming data to handle
 * This data is just pushed up to the application layer.
 */
static void hidReadCB(const struct device *dev)
{
    if (dev != NULL) {
        uint8_t message[BLOCK_SIZE];
        size_t readSize = 0;
        hid_int_ep_read(dev, (uint8_t *)&message, sizeof(message), &readSize);

        if (usb_device.callbacks.data_received != NULL) {
            usb_device.callbacks.data_received(&usb_device, message, sizeof(message),
                                               usb_device.callbackData);
        }
    }
}

/**
 * @brief HID write callback
 *
 * @param dev USB dev pointer
 *
 * This function is called by Zephyr when a data block is sent
 * and the system is ready to send the next.
 */
static void hidWriteCB(const struct device *dev)
{
    ARG_UNUSED(dev);
    worker_submit(&usb_device.sendWorker);
}

static const struct hid_ops ops = {
    .int_out_ready = hidReadCB,
    .int_in_ready = hidWriteCB,
};

static void usbStatusCallback(enum usb_dc_status_code status, const uint8_t *param)
{
    switch (status) {
    case USB_DC_RESET:
        usb_device.configured = false;
        break;
    case USB_DC_CONFIGURED:
        if (!usb_device.configured) {
            usb_device.configured = true;
        }
        break;
    case USB_DC_SOF:
        break;
    case USB_DC_SUSPEND:
        send_usb_connection_status(false);
        LOG_DBG("suspend");
        break;
    case USB_DC_RESUME:
        send_usb_connection_status(true);
        LOG_DBG("resume");
        break;
    default:
        LOG_DBG("status %u unhandled", status);
        break;
    }
}

static int usbPreInit()
{
    usb_device.configured = false;
    usb_device.callbackData = NULL;
    usb_device.workerRunning = false;
    usb_device.dev = device_get_binding("HID_0");

    if (usb_device.dev == NULL) {
        LOG_ERR("Cannot get USB HID Device");
        return -ENODEV;
    }

    LOG_INF("HID Device: dev %p", usb_device.dev);

    usb_hid_register_device(usb_device.dev, hid_report_desc, sizeof(hid_report_desc), &ops);

    return usb_hid_init(usb_device.dev);
}

int h_usb_initalize()
{
    int preInitRepsone = usbPreInit();
    if (preInitRepsone != 0) {
        LOG_ERR("PreInit failed %d", preInitRepsone);
        return preInitRepsone;
    }

    int ret = usb_enable(usbStatusCallback);
    if (ret != 0) {
        LOG_ERR("Failed to enable USB");
        return 0;
    }

    k_work_init(&usb_device.sendWorker, sendUsbWorker);

    return 0;
}

usb_dev_t *get_usb_device()
{
    return &usb_device;
}

int h_usb_set_callbacks(usb_dev_t *dev, h_usb_callbacks_t *callbacks, void *callback_data)
{
    if (dev != NULL) {
        dev->callbacks.data_received = callbacks->data_received;
        dev->callbackData = callback_data;
        return 0;
    }

    return -1;
}

int h_usb_send_data(usb_dev_t *dev, const uint8_t *data, const size_t size)
{
    // Copy data in to zero filled buffer
    uint8_t msg[BLOCK_SIZE];
    memset(msg, 0, sizeof(msg));
    memcpy(msg, data, MIN(size, sizeof(msg)));

    // Copy to queue
    if (k_msgq_put(&usbSendQueue, msg, K_MSEC(1000)) != 0) {
        LOG_ERR("send: timeout sending packet");
        return 0;
    }

    // Start worker
    startWorker(dev);

    return size;
}
