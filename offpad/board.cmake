board_runner_args(stm32cubeprogrammer "--port=swd" "--reset-mode=hw" "--frequency=4000")
board_runner_args(pyocd "--target=stm32wb55rgvx")

include(${ZEPHYR_BASE}/boards/common/stm32cubeprogrammer.board.cmake)
include(${ZEPHYR_BASE}/boards/common/openocd.board.cmake)
include(${ZEPHYR_BASE}/boards/common/pyocd.board.cmake)
