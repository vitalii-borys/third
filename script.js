/* for (var i = 1; i < 3; i++)
{console.log(i);}

for (d = 0; d < 6; d++)
{
    if (d % 2 == 0)
    {
        continue;
    }
    console.log(d + " то є непарне число.")
}

var myArray = ["What is the meaning of life?", "The meaning of life is", 42];

for (e = 0; e < myArray.length; e++)
{
    console.log(myArray[e]);
} */

/*function greet(name)
{
    return ("Привіт, " + name + " !")
}
console.log(greet("Bob"));p*/
/* for (var i = 1; i < 31; i = i + 1)
{console.log(i + "-й крок" + " i = " + i);}
for (var a = 1; a < 31; a = Math.pow(2, a - 1))
{console.log(a + "a");} */
var canvas = document.body.appendChild( document.createElement( 'canvas' ) ),
    context = canvas.getContext( '2d' );
context.globalCompositeOperation = 'lighter';
canvas.width = 1080;
canvas.height = 1920;
draw();

var textStrip = ['诶', '比', '西', '迪', '伊', '吉', '艾', '杰', '开', '哦', '屁', '提', '维'];

var stripCount = 60, stripX = new Array(), stripY = new Array(), dY = new Array(), stripFontSize = new Array();

for (var i = 0; i < stripCount; i++) {
    stripX[i] = Math.floor(Math.random()*1265);
    stripY[i] = -100;
    dY[i] = Math.floor(Math.random()*7)+3;
    stripFontSize[i] = Math.floor(Math.random()*16)+16;
}

var theColors = ['#cefbe4', '#81ec72', '#5cd646', '#54d13c', '#4ccc32', '#43c728'];

var elem, context, timer;

function drawStrip(x, y) {
    for (var k = 0; k <= 20; k++) {
        var randChar = textStrip[Math.floor(Math.random()*textStrip.length)];
        if (context.fillText) {
            switch (k) {
            case 0:
                context.fillStyle = theColors[0]; break;
            case 1:
                context.fillStyle = theColors[1]; break;
            case 3:
                context.fillStyle = theColors[2]; break;
            case 7:
                context.fillStyle = theColors[3]; break;
            case 13:
                context.fillStyle = theColors[4]; break;
            case 17:
                context.fillStyle = theColors[5]; break;
            }
            context.fillText(randChar, x, y);
        }
        y -= stripFontSize[k];
    }
}

function draw() {
    // clear the canvas and set the properties
    context.clearRect(0, 0, canvas.width, canvas.height);
    context.shadowOffsetX = context.shadowOffsetY = 0;
    context.shadowBlur = 8;
    context.shadowColor = '#94f475';
    
    for (var j = 0; j < stripCount; j++) {
        context.font = stripFontSize[j]+'px MatrixCode';
        context.textBaseline = 'top';
        context.textAlign = 'center';
        
        if (stripY[j] > 1358) {
            stripX[j] = Math.floor(Math.random()*canvas.width);
            stripY[j] = -100;
            dY[j] = Math.floor(Math.random()*7)+3;
            stripFontSize[j] = Math.floor(Math.random()*16)+8;
            drawStrip(stripX[j], stripY[j]);
        } else drawStrip(stripX[j], stripY[j]);
        
        stripY[j] += dY[j];
    }
  setTimeout(draw, 70);
}

