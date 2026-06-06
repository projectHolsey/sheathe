all: main hw web system

main: 
	gcc main.c monitorSystem/sys_monitor.c monitorWeb/net_monitor.c monitorHardware/hw_monitor.c -o main

hw:
	gcc monitorHardware/hw_main.c monitorHardware/hw_monitor.c -o monitorHardware/hw
# build and run
run-hw: hw
	./monitorHardware/hw


# build only
web:
	gcc monitorWeb/main.c monitorWeb/net_monitor.c -o monitorWeb/web
# build and run
run-web: web
	./monitorWeb/web


# build only
sys:
	gcc monitorSystem/sysmain.c monitorSystem/sys_monitor.c -o monitorSystem/sys
# build and run
run-sys: sys
	./monitorSystem/sys