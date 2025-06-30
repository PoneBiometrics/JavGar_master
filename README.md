# FROST Threshold Signatures Implementation

This repository contains a practical implementation of FROST (Flexible Round-Optimized Schnorr Threshold) signatures for authentication. The implementation demonstrates a T-out-of-N threshold signature scheme using embedded development boards and a coordinating computer.

## Overview

The system implements threshold signatures where:
- **3 participants** hold secret shares of a signing key
- **2 participants** are required to generate a valid signature (threshold)
- A computer acts as **coordinator** and **trusted dealer**
- Communication uses **UART** (Nucleo-L476RG) and **USB HID** (OFFPAD)

The implementation follows the FROST protocol with two main phases:
1. **Key Generation**: Computer generates and distributes secret shares to boards
2. **Signing**: Boards collaborate to sign messages using threshold cryptography

## Directory Structure

```
├── presign_pc/src/          # PC key generation and distribution
├── receive_usb_nucleo/      # Nucleo board firmware for key reception
├── receive_usb_offpad/      # OFFPAD board firmware for key reception  
├── signing_nucleo/          # Nucleo board firmware for signing
├── signing_offpad/          # OFFPAD board firmware for signing
├── signing_pc/src/          # PC signing coordinator
├── presign_pc_tests/src/    # PC key generation and distribution tests
├── signing_nucleo_tests/src/    # Nucleo board firmware for signing tests
└── signing_offpad_tests/src/    # OFFPAD board firmware for signing tests
```

## Hardware Requirements

- **Computer**: Windows machine with GCC compiler
- **STM32 Nucleo-L476RG**: Development board with UART communication
- **OFFPAD**: Development board with USB HID communication
- **USB cables**: For board connections and power

## Dependencies

- **secp256k1**: Elliptic curve cryptography library
- **Zephyr RTOS**: For embedded board firmware
- **West**: Zephyr build tool
- **GCC**: For PC compilation

## Build Instructions

### 1. Computer Firmware

Navigate to the key generation or signing directory and build the executable:

#### Computer (Key Generation)
```bash
cd presign_pc/src
gcc -g main.c -lsecp256k1 -lsetupapi -lhid -o keygen.exe
```

#### Computer (Signing)
```bash
cd signing_pc/src
gcc -g main.c -lsecp256k1 -lsetupapi -lhid -o main.exe
```

**Required libraries:**
- `secp256k1`: Cryptographic operations
- `setupapi`: Windows device enumeration
- `hid`: USB HID communication

### 2. Board Firmware

For each board directory, build and flash the firmware using West:

#### Nucleo Board (Key Reception)
```bash
cd receive_usb_nucleo
west build
west flash
```

#### OFFPAD Board (Key Reception)
```bash
cd receive_usb_offpad
west build
west flash
```

#### Nucleo Board (Signing)
```bash
cd signing_nucleo
west build
west flash
```

#### OFFPAD Board (Signing)
```bash
cd signing_offpad
west build
west flash
```

## Running the Implementation

### Phase 1: Key Generation and Distribution

1. **Flash key reception firmware** to all boards:
   - Flash `receive_usb_nucleo` to Nucleo-L476RG
   - Flash `receive_usb_offpad` to OFFPAD

2. **Run key generation** on computer:
   ```bash
   cd presign_pc/src
   ./main.exe
   ```

3. **Select communication method** for each board:
   - Choose UART for Nucleo (specify COM port, e.g., COM4)
   - Choose USB HID for OFFPAD

4. **Key distribution**: The computer will generate secret shares and distribute them to each board using their respective communication protocols.

### Phase 2: Signing

1. **Flash signing firmware** to boards:
   - Flash `signing_nucleo` to Nucleo-L476RG  
   - Flash `signing_offpad` to OFFPAD

2. **Run signing coordinator** on computer:
   ```bash
   cd signing_pc/src
   ./main.exe
   ```

3. **Threshold signing**: The coordinator will:
   - Send ready signal to participants
   - Collect nonce commitments (Round 1)
   - Send message hash and commitments (Round 2)  
   - Aggregate signature shares into final signature

## Important UART Configuration

**Critical**: For UART communication, you must update the UART configuration in the board code to match your specific board setup.

In the Nucleo firmware files, modify the UART device node:
```c
#define UART_DEVICE_NODE DT_NODELABEL(usart1)  // Change as needed
```

Check your board's pin configuration and update accordingly.

## Communication Protocols

### UART (Nucleo-L476RG)
- **Baud Rate**: 115200
- **Data Bits**: 8
- **Stop Bits**: 1
- **Parity**: None
- **Flow Control**: None

### USB HID (OFFPAD)
- **Vendor ID**: 0x2FE3
- **Product ID**: 0x0100
- **Report Size**: 64 bytes
- **Communication**: Bidirectional

## Protocol Flow

### Key Generation
1. Computer generates master secret key
2. Creates secret shares using Shamir's secret sharing
3. Distributes shares to boards via UART/USB HID
4. Boards verify and store shares in flash memory

### Signing Process
1. **Round 1**: 
   - Computer sends ready signal
   - Boards generate nonces and commitments
   - Computer collects commitments
   
2. **Round 2**:
   - Computer sends message hash and all commitments
   - Boards compute signature shares
   - Computer aggregates shares into final signature

## Security Features

- **Secret shares never leave boards** after distribution
- **Commitment verification** before signature computation
- **Threshold security**: Requires 2 out of 3 participants

## Troubleshooting

### Common Issues

1. **UART Connection Failed**:
   - Verify COM port number
   - Check UART_DEVICE_NODE configuration
   - Ensure proper baud rate (115200)

2. **USB HID Device Not Found**:
   - Check USB cable connection
   - Verify VID/PID in device manager
   - Try different USB port

3. **Build Failures**:
   - Ensure West and Zephyr SDK are properly installed
   - Check secp256k1 library installation
   - Verify GCC and development tools

4. **Flash Storage Issues**:
   - Ensure flash partition is properly configured
   - Check available flash memory
   - Verify flash area permissions