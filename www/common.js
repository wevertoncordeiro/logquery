
function changeColor(tr, opt) {
  if (tr.style) {
    var color1 = tr.style.backgroundColor;
    var my_white = "";
    var my_brown = "#e5e5e5";

    if (color1.compareColor(my_white)) {
      tr.style.backgroundColor = my_brown;
    } else if (color1.compareColor(my_brown)) {
      tr.style.backgroundColor = my_white;
    }
  }
  return true;
}

String.prototype.compareColor = function() {
  if((this.indexOf("#") != -1 && arguments[0].indexOf("#") != -1) || 
    (this.indexOf("rgb") != -1 && arguments[0].indexOf("rgb") != -1)){
    return this.toLowerCase() == arguments[0].toLowerCase()
  } else {
    xCol_1 = this;
    xCol_2 = arguments[0];
    if(xCol_1.indexOf("#") != -1)xCol_1 = xCol_1.toRGBcolor();
    if(xCol_2.indexOf("#") != -1)xCol_2 = xCol_2.toRGBcolor();
    return xCol_1.toLowerCase() == xCol_2.toLowerCase()
  }
}

String.prototype.toRGBcolor = function(){
  varR = parseInt(this.substring(1,3), 16);
  varG = parseInt(this.substring(3,5), 16);
  varB = parseInt(this.substring(5,7), 16);
  return "rgb(" + varR + ", " + varG + ", " +  varB + ")";
}

