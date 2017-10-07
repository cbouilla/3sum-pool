#!/usr/bin/env python3
from persistence import WorkerDB


if __name__ == "__main__":
    db = WorkerDB()
    for _, pworker in db.workers.items():
        print(pworker)