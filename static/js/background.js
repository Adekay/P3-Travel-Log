var images = [
  "/static/images/background1.jpg",
  "/static/images/background2.jpg",
  "/static/images/background3.jpg",
  "/static/images/background4.jpg",
  "/static/images/background5.jpg",
  "/static/images/background6.jpg",
  "/static/images/background7.jpg"
];

var $body = $("body"),
    $bg = $("#bg");


function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

var image_url = images[getRandomInt(0, images.length - 1)];
$bg.hide().css({backgroundImage : "url("+image_url+")"}).fadeTo(1000, 1, function(){
  $bg.css({backgroundImage : "url("+image_url+")"}); 
});
