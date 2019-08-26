TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
LIBS += -lnetfilter_queue

SOURCES += \
        main.cpp \
        netfilter_test.cpp \
        packet.cpp

HEADERS += \
    netfilter_test.h \
    packet.h
