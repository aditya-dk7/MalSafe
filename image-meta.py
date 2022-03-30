import os,sys

#importing the Image class from PILLOW module
import PIL.Image

#importing the ExifTags class from PILLOW module
from PIL.ExifTags import TAGS

def view_exif_img(imgloc):

     #check if path exists
     if os.path.isfile(imgloc):
        ret = {}
        i = PIL.Image.open(imgloc)
        info = i._getexif()
        #check if tags exists or not
        if info is not None:

                #looping through the tags to display metadata
                for tag, value in info.items():

                         decoded = TAGS.get(tag, tag)

                         print(decoded,value)
        #prompt if no exif data exists
        else:
            print("The file has no exif data.")
            sys.exit(0)            


view_exif_img(sys.argv[1])