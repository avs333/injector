
# Change as appropriate!
NDK_PATH=/mnt/new/android-ndk-r14

SYSROOT=$(NDK_PATH)/platforms/android-24/arch-arm
CC=$(NDK_PATH)/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin/arm-linux-androideabi-gcc --sysroot=$(SYSROOT)

CFLAGS = -c -O3 -Wall -mthumb

all: patch_func.o

