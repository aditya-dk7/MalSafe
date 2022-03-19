import base64
with open("/home/dk7/projectsCap/MalSafe/PEModule/cmd.exe", "rb") as img_file:
    my_string = base64.b64encode(img_file.read())

with open("/home/dk7/projectsCap/MalSafe/base64_test.txt", 'wb') as f:
    f.write(my_string)

