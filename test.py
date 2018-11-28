print("Here are the Current Elements: 12, 12.25, 14.1, -67, 128, -22.35")
array = [12, 12.25, 14.1, -67, 128, -22.35]
input = input("Enter the User Input Element: ")
for value in array:
    if int(input) == value:
        array.remove(value)

print(array)
