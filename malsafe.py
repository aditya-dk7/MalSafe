import sys
sys.path.insert(0, '/home/dk7/projectsCap/MalSafe/URLModule')
sys.path.insert(1, '/home/dk7/projectsCap/MalSafe/PEModule')
import os
from flask import Flask, jsonify, request
from flask_restful import Api, Resource
import base64
import pefile
from URLModule import url_ssl_verf
from PEModule import pe_test
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
        posted_type_extension = posted_data['posted_extension'] #exe etc.
  
        if posted_type == "file":
            posted_data = base64.b64decode(posted_input_stream)
            filename = os.path.join(os.path.dirname("downloads/"), posted_hashmd5+"." + posted_type_extension)
            with open(filename, 'wb') as f:
                f.write(posted_data)
            string = 'exiftool/exiftool -j ' + filename
            metaInfo = os.popen(string).read()
            metaInfo = json.loads(metaInfo)
            fileResult = {}
            fileResult['metaInfo'] = metaInfo
            fileResult['md5'] = posted_hashmd5
            try:
                pefile.PE(filename)
                fileResult['peInfo'] = pe_test.predictMalicious(filename)
            except:
                fileResult['peInfo'] = {}
            return jsonify(fileResult)

        elif posted_type == "url":
            posted_data = base64.b64decode(posted_input_stream).decode('utf-8')
            x = url_ssl_verf.url_cert_info(posted_data)
            return jsonify({
                'result': x
            })
        else:
            return jsonify({
                'Process': "Failed"
            })


api.add_resource(MakePrediction, '/malsafe')


if __name__ == '__main__':
    app.run(debug=True)