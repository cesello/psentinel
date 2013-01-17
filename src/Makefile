
LIBS := -lrt
RM := rm -rf
CC := gcc
CFLAGS  := -O3

prefix :=/usr/local
PROGRAM := psentinel
LIST_FILES := psentinel
CONFIG_FILES := psentinel.cfg

# Add inputs and outputs from these tool invocations to the build variables

# Add inputs and outputs from these tool invocations to the build variables
C_SRCS += \
./checkers.c \
./general.c \
./ini.c \
./main.c \
./minischeduler.c \
./networking.c

OBJS += \
./checkers.o \
./general.o \
./ini.o \
./main.o \
./minischeduler.o \
./networking.o

C_DEPS += \
./checkers.d \
./general.d \
./ini.d \
./main.d \
./minischeduler.d \
./networking.d


# Each subdirectory must supply rules for building sources it contributes
%.o: ./%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	$(CC) $(CFLAGS) -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


# All Target
all: $(PROGRAM)

# Tool invocations
$(PROGRAM): $(OBJS) 
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C Linker'
	$(CC)  -o $@ $(OBJS) $(LIBS)
	@echo 'Finished building target: $@'
	@echo ' '

# Other Targets
clean:
	-$(RM) $(OBJS)$(C_DEPS)$(EXECUTABLES) $(PROGRAM)
	-@echo ' '

install: all
	test -d $(prefix)/$(PROGRAM) || mkdir $(prefix)/$(PROGRAM)
	for prog in $(LIST_FILES); do \
		install -m 0755 $$prog $(prefix)/$(PROGRAM); \
	done
	test -d /etc/$(PROGRAM) || mkdir /etc/$(PROGRAM)
	for cfg in $(CONFIG_FILES); do \
		install -m 0644 $$cfg /etc/$(PROGRAM); \
	done
	test -d /var/run/$(PROGRAM) || mkdir /var/run/$(PROGRAM)
	test -L /usr/bin/$(PROGRAM) || ln -s $(prefix)/$(PROGRAM)/$(PROGRAM) /usr/bin/$(PROGRAM)


.PHONY: install
