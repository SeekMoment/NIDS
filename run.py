from models.runner import Runner

dataset = 0

while True:
    try:
        run_type = int(
            input("Выберите тип классификации:\r\n0. Бинарная\r\n1. Мультиклассовая\r\n"))
        if not (0 <= run_type <= 1):
            raise Exception
    except Exception:
        print("\r\nНеправильный выбор!\r\n")
        continue
    break
while True:
    try:
        model_type = int(
            input("Выберите алгоритм:\r\n0. СNN\r\n1. "
                  "DNN\r\n2. RNN\r\n")
        )
        if not (0 <= model_type <= 3):
            raise Exception
    except Exception:
        print("\r\nНеправильный выбор!\r\n")
        continue
    try:
        epochs = int(
            input(
                "Выберите количество эпох:\r\n0. 5\r\n1. 25\r\n2. "
                "50\r\n3. 100\r\n4. 250\r\n5. 500\r\n"))
        if not (0 <= epochs <= 4):
            raise Exception
        epochs_num = 0
        if epochs == 0:
            epochs_num = 5
        elif epochs == 1:
            epochs_num = 25
        elif epochs == 2:
            epochs_num = 50
        elif epochs == 3:
            epochs_num = 100
        elif epochs == 4:
            epochs_num = 250
        elif epochs == 5:
            epochs_num = 500
    except Exception:
        print("\r\nНеправильный выбор!\r\n")
        continue
    break

Runner.run(run_type, dataset, model_type, epochs_num)
