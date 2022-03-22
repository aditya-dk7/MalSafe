import os
from flask import Flask, jsonify, request
from flask_restful import Api, Resource
import base64
import pefile
import URLModule.url_ssl_verf as url_ssl_verf
import PEModule.pe_test as pe_test
import json

app = Flask(__name__)
api = Api(app)


class MakePrediction(Resource):
    @staticmethod
    def post():
        posted_data = request.get_json()
        posted_hashmd5 = posted_data['hashmd5'] 
        posted_input_stream = posted_data['input_stream'] #base64 data
        posted_type = posted_data['posted_type'] #url, file
  
        if posted_type == "file":
            posted_data = base64.b64decode(posted_input_stream)
            filename = os.path.join(os.path.dirname("downloads/"), posted_hashmd5)
            with open(filename, 'wb') as f:
                f.write(posted_data)
            string = 'exiftool/exiftool -j ' + filename
            metaInfo = os.popen(string).read()
            metaInfo = json.loads(metaInfo)
            fileResult = {}
            fileResult['metaInfo'] = metaInfo
            fileResult['md5'] = posted_hashmd5
            if "PEType" in metaInfo[0]:
                try:
                    pefile.PE(filename)
                    fileResult['peInfoMalicious'] = pe_test.predictMalicious(filename)
                except:
                    fileResult['peInfoMalicious'] = {}
            elif metaInfo[0]["FileType"] == "JPEG":
                #TODO: Add your JPEG code here.
                print("JPG Recieved")
            return jsonify(fileResult)
        elif posted_type == "url":
            posted_data = base64.b64decode(posted_input_stream).decode('utf-8')
            urlResult = {}
            urlResult['cert_info'] = url_ssl_verf.url_cert_info(posted_data)
            #TODO: Call your function here and add the result to urlResult.
            return jsonify(urlResult)
        else:
            return jsonify({
                'Process': "Failed"
            })


api.add_resource(MakePrediction, '/malsafe')


if __name__ == '__main__':
    app.run(debug=True)