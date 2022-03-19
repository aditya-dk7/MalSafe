import sys
sys.path.insert(0, '/home/dk7/projectsCap/MalSafe/URLModule')
import os
from flask import Flask, jsonify, request
from flask_restful import Api, Resource
import joblib
import base64
import numpy as np
import pickle
from URLModule import url_ssl_verf
from url_ssl_verf import web_scraper
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
            with open(filename, 'w') as f:
                f.write(posted_data)
        elif posted_type == "url":
            posted_data = base64.b64decode(posted_input_stream).decode('utf-8')
            x = url_ssl_verf.url_cert_info(posted_data)
            return jsonify({
                'result': x
            })
        try:
            return jsonify({
                # 'IMAGE': ret_img_base64.decode(),
                # 'TEMPERATURE': person_temperature
            })
        except:
            return jsonify({
                'Process': "Failed"
            })


api.add_resource(MakePrediction, '/malsafe')


if __name__ == '__main__':
    app.run(debug=True)