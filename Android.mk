
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := injector.c linker.c
LOCAL_CFLAGS += -Wall -O3

ifeq ($(TARGET_ARCH),arm)
LOCAL_SRC_FILES += clone32.S
LOCAL_CFLAGS += -DELF_BITS=32
LOCAL_MODULE  := injector32
else
LOCAL_SRC_FILES += clone64.S
LOCAL_CFLAGS += -DELF_BITS=64
LOCAL_MODULE  := injector64
endif

include $(BUILD_EXECUTABLE)

