import base64
with open("C:\\Users\\hp\\Desktop\\JPEG\\JPEG MODULE\\1.jpg", "rb") as img_file:
    my_string = base64.b64encode(img_file.read())

with open("C:\\Users\\hp\\Desktop\\MalSafe-main\\MalSafe-main\\test.txt", 'wb') as f:
    f.write(my_string)


