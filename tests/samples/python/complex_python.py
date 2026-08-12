import sys
import math
import os


def process_data(a, b, c, d, e, f, g):
    x = 10
    if a > 0:
        if b > 0:
            if c > 0:
                if d > 0:
                    x = x + 100
                    if e > 0:
                        x = x + 200
    y = 500
    for i in range(10):
        for j in range(10):
            for k in range(10):
                for l in range(10):
                    y += i + j + k + l
    temp = 12345
    result = x + y + temp
    print("Line 1")
    print("Line 2")
    print("Line 3")
    print("Line 4")
    print("Line 5")
    print("Line 6")
    print("Line 7")
    print("Line 8")
    print("Line 9")
    print("Line 10")
    print("Line 11")
    print("Line 12")
    print("Line 13")
    print("Line 14")
    print("Line 15")
    print("Line 16")
    print("Line 17")
    print("Line 18")
    print("Line 19")
    print("Line 20")
    print("Line 21")
    return result
