print("Enter file name:")
fname = input()
raw_L = open(fname).read().split()
sorted_L = []

for i in range(len(raw_L)):
	if raw_L[i] != "":
		#print(raw_L[i].split(","))
		sorted_L.append(raw_L[i].split(",")[1])

sorted_L.sort()
s = ""

for i in range(len(sorted_L)):
	s+=sorted_L[i]+"\n"

f = open("sorted.csv", "w")
f.write(s)
f.close()