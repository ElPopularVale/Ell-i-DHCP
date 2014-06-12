#include "stm32f0xx.h"
#include "stm32f0xx_gpio.h"
#include "stm32f0xx_rcc.h"
#include "enc28j60.h"
#include "usart.h"
#include "ipstack.h"
#include "dhcp.h"
#include <stdio.h>

int main(void) {
	usartInit();
	IPstackInit();
	printf("Hello world from main\r");
	while (1) {
		IPstackIdle();
	}
}
