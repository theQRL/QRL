import csv
import simplejson as json
from decimal import Decimal
from qrl.core import config


def main():
    json_data = dict()

    with open('data/token_migration.csv') as f:
        data = csv.reader(f, delimiter=',')

        shor_per_quanta = int(config.dev.shor_per_quanta)
        count = 0
        for row in data:
            count += 1
            json_data[row[0]] = int(Decimal(row[1]) * shor_per_quanta)

        if count != len(json_data.keys()):
            raise Exception('There must be duplicate address in csv file.')

    with open('data/token_migration.json', 'w') as f:
        json.dump(json_data, f)


if __name__ == '__main__':
    main()
