from tensorflow.keras.layers import Dense, Activation, Dropout, Flatten
from tensorflow.keras.models import Sequential


class DNNModel:

    @classmethod
    def model(cls, run_type, shapes):
        model = Sequential()
        model.add(Dense(128, input_shape=shapes, activation='relu'))
        model.add(Dropout(0.1))
        model.add(Dense(256, activation='relu'))
        model.add(Dropout(0.1))
        model.add(Dense(128, activation='relu'))
        model.add(Dropout(0.1))

        model.add(Flatten())
        #
        if run_type == 0:
            model.add(Dense(1))
            model.add(Activation('sigmoid'))
        else:
            model.add(Dense(5))
            model.add(Activation('softmax'))

        return model
