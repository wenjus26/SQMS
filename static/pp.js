document.getElementById("origin").addEventListener("change", function(){
    var otherOrigin = document.getElementById("other_origin");
    if(this.value==="other"){
        otherOrigin.style.display="block";
    }else{
        otherOrigin.style.display="none";
}
})


document.getElementById("location").addEventListener("change", function(){
    var otherloca = document.getElementById("other_lo");
    if(this.value==="otherlocation"){
        otherloca.style.display="block";
    }else{
        otherloca.style.display="none";
}
})

document.getElementById("other_lo").addEventListener("change", function(){
    var external = document.getElementById("external");
    if(this.value==="externallo"){
        external.style.display="block";
    }else{
        external.style.display="none";
}
})




document.getElementById("sample").addEventListener("change", function(){
    var samples = document.getElementById("sampletext");
    if(this.value==="ms"){
       samples.style.display="block";
    }else{
        samples.style.display="none";
}
})


