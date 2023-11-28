// JavaScript function to generate 6 random unique values in order and populate form
function luckyDip() {

    // create empty set
    let draw = new Set();

    randomBuffer = new Uint32Array(6);
    window.crypto.getRandomValues(randomBuffer);

    for (let i=0; i < randomBuffer.length; i++){
        csRandomNumber = randomBuffer[i] / (0xFFFFFFFF)
        min = 1;
        max = 60;
        value = Math.floor(csRandomNumber * (max - min+ 1) + min);

        // sets cannot contain duplicates so value is only added if it does not exist in set
        draw.add(value)
    }

    // turn set into an array
    let a = Array.from(draw);

    // sort array into size order
    a.sort(function (a, b) {
        return a - b;
    });

    // add values to fields in create draw form
    for (let i = 0; i < 6; i++) {
        document.getElementById("no" + (i + 1)).value = a[i];
    }
}