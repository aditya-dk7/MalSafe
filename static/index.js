function test(){
    if (t.match(regex)) {
        console.log("Good Job");
      } else {
        feedback.style.display = "block"
      }
}

const submitBtn = document.getElementById('submit_btn');


var expression = /[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)?/gi;
var regex = new RegExp(expression);
var t = document.getElementById('url_input').value;
var feedback = document.getElementById('url_feedback');


submitBtn.addEventListener('click', test)

