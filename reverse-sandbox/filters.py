import json
import os


def read_filters():
    temp = {}
    filters = {}
    script_dir = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(script_dir, "misc/filters.json")) as data:
        temp = json.load(data)

        for key, value in temp.items():
            filters[int(str(key), 16)] = value

    return filters


class Filters(object):

    filters = read_filters()

    @staticmethod
    def exists(id):
        return id in Filters.filters

    @staticmethod
    def get(id):
        return Filters.filters.get(id, None)
