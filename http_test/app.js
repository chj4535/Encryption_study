//wireshark로 local 전송하는거 안나오는 경우가 있다!
//다른 컴퓨터로 접속해서 http://ip주소/login 로 입력하고 http.request.method=="POST"로 id,password 확인!
//다른 컴퓨터로 접속해서 https://ip주소/login 로 입력하고 tcp.port==443로 암호화된것 확인

//https로 연결되면

//클라이언트가 서버에 접속 = Client Hello
//클라이언트가 생성한 랜덤 데이터를 보냄 + 암호화 방식

//서버의 응답 = server hello
//서버가 생성한 랜덤 데이터 + 인증서

//클라이언트가 인증서가 CA에 의해 발급된 것인지 확인(우리가 openssl로 만든건 CA가 등록되지 않아서 인증되지 않은 인증서라 나옴)
//클라이언트가 '클라이언트 랜덤 데이터' + '서버 랜덤 데이터' 를 합쳐서 pre master secret 를 만듬

//pre master secret를 인증서에 들어있는 공개키를 이용해서 암호화 하고 서버로 전송(공개키 암호화)

//서버는 pre master secret를 개인키로 복호화함
//서버, 클라이언트 둘다 pre master secret로 master secret를 만들고 이를 이용해서 세션키를 만듬

//이후 세션키를 이용해 대칭키 암호화 통신을 함

//이후 통신 종료되면 세션키 폐기


////////////////의문/////////////////////////
//의문 pre master secret와 master secret의 차이
//세션키는 master secret의 무엇으로 만드는가

//이후 통신이 종료되면 master secret는 유지 되는가?
////////////////의문/////////////////////////


var http=require('http'),
    https = require('https'),
    express = require('express'),
     fs = require('fs');

var options = {
    key: fs.readFileSync(__dirname+'/openssl/key.pem'), //개인키
    cert: fs.readFileSync(__dirname+'/openssl/cert.pem') //공개키
};


var port1 = 80; //http => wireshark로 보임
var port2 = 443; //https => wireshark로 안보임

var app = express();
app.use(express.urlencoded());

http.createServer(app).listen(port1, function(){
  console.log("Http server listening on port " + port1);
});


https.createServer(options, app).listen(port2, function(){
  console.log("Https server listening on port " + port2);
});

app.get('/', function (req, res) {
    res.writeHead(200, {'Content-Type' : 'text/html'});
    res.write('<h3>Welcome</h3>');
    res.write('<a href="/login">Please login</a>');
    res.end();
});

app.get('/login', function (req, res){
    res.writeHead(200, {'Content-Type': 'text/html'});
    res.write('<h3>Login</h3>');
    res.write('<form method="POST" action="/login">');
    res.write('<label name="userId">UserId : </label>')
    res.write('<input type="text" name="userId"><br/>');
    res.write('<label name="password">Password : </label>')
    res.write('<input type="password" name="password"><br/>');
    res.write('<input type="submit" name="login" value="Login">');
    res.write('</form>');
    res.end();
})

app.post('/login', function (req, res){
  console.log(req.body);
    var userId = req.params.userId;
    var password = req.params.password;

    res.writeHead(200, {'Content-Type': 'text/html'});
    res.write('Thank you, '+userId+', you are now logged in.');
    res.write('<p><a href="/"> back home</a>');
    res.end();
});
