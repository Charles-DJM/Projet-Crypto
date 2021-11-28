with open("correspondence.csv", "r") as file: 
    datafile = file.readlines()
for line in datafile: 
    a, b, c, d = line.split(",")
    if d == "5d1x7w1s5srgdrgdgrgrdw4d7d\n" :
        print(line)