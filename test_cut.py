string = "user=admin&pass=thunder&input=123"
# string = "/get.php?field=testing"
arr = []

while "&" in string:
    temp = string.split("&", 1)[0]
    if string.split("&", 1)[1] :
        string = string.split("&", 1)[1]
    arr.append(temp)
arr.append(string)
print(arr)