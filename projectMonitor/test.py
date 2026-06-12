import time

counter = 0

while True:
    time.sleep(10)
    with open("test.txt", "w") as f:
        counter += 1
        f.write("Hi : " + str(counter))