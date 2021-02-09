import re
import timeit
import matplotlib.pyplot as plt

def test(input):
    re.search("^([a-zA-Z0-9])(([\-.]|[_]+)?([a-zA-Z0-9]+))*(@){1}[a-z0-9]+[.]{1}(([a-z]{2,3})|([a-z]{2,3}[.]{1}[a-z]{2,3}))$", input)

if __name__ == '__main__':
    import timeit
    times = []
    for i in range(1, 25):
        times.append(timeit.timeit("test('a'*" +str(i)+")", setup="from __main__ import test", number=5))
    plt.plot(list(range(1,25)), times)
    plt.ylabel("Average Regex Search Time")
    plt.xlabel("Length of input")
    plt.show()
