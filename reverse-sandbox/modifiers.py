import json


def read_modifiers():
    modifiers = {}
    with open("misc/modifiers_functions.json") as data:
        temp = json.load(data)

        for key, value in temp.items():
            modifiers[int(str(key), 16)] = value

    return modifiers


class Modifiers(object):

    modifiers = read_modifiers()

    @staticmethod
    def exists(id):
        return id in Modifiers.modifiers

    @staticmethod
    def get(id):
        return Modifiers.modifiers.get(id, None)
