import matplotlib.pyplot as plt
labels = 'Encode', 'Encrypt', 'Computation', 'Decode', 'Decrypt'
colors = ['gold', 'green', 'lightskyblue', 'red', 'violet']
sizes = [42093019, 51076003, 40837398, 208, 11373]
plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%')
plt.axis('equal')
plt.show()
