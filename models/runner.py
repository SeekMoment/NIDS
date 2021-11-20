import time

import numpy as np
from tensorflow.keras.optimizers import Adam
from tensorflow.keras import utils
from sklearn.metrics import classification_report, confusion_matrix


from NIDS.models.conv1d import Conv1DModel
from NIDS.models.dnn import DNNModel
from NIDS.models.rnn import RNNModel
from NIDS.services.process import Processor


class Runner:

    @classmethod
    def run(cls, run_type, dataset, model_type, epochs):
        x_train, y_train, x_test, y_test = Processor.get_data(
            run_type,
            dataset,
        )

        # reshape [samples, timesteps, features]
        x_train = x_train.reshape(x_train.shape[0], 1, x_train.shape[1])
        x_test = x_test.reshape(x_test.shape[0], 1, x_test.shape[1])

        if run_type == 1:
            y_train = utils.to_categorical(y_train)
            y_test = utils.to_categorical(y_test)

        start = time.time()
        if model_type == 0:
            model = Conv1DModel.model(
                run_type,
                (x_train.shape[1], x_train.shape[2]),
            )
        elif model_type == 1:
            model = DNNModel.model(
                run_type,
                (x_train.shape[1], x_train.shape[2]),
            )
        elif model_type == 2:
            model = RNNModel.model(
                run_type,
                (x_train.shape[1], x_train.shape[2]),
            )

        model.summary()

        # optimizer
        adam = Adam(lr=0.0005)

        if run_type == 0:
            model.compile(
                optimizer=adam,
                loss='binary_crossentropy',
                metrics=['accuracy'],
            )
        else:
            model.compile(
                optimizer=adam,
                loss='categorical_crossentropy',
                metrics=['accuracy'],
            )

        model.fit(
            x_train,
            y_train,
            validation_data=(x_test, y_test),
            epochs=epochs,
            batch_size=32,
        )
        stop = time.time()
        loss, accuracy = model.evaluate(x_test, y_test, batch_size=32)
        print("\nВремя работы: %s секунд \n" % (int(stop - start)))
        print("\nLoss: %.2f, Accuracy: %.2f%%" % (loss, accuracy * 100))

