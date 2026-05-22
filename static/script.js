const socket = io();

function startScan(){

    const target = document.getElementById("target").value;

    if(!target){
        alert("Enter target URL");
        return;
    }

    document.getElementById("terminal").innerHTML = "";
    document.getElementById("report").innerHTML = "";

    document.getElementById("scan-status").innerHTML = "Status: Running Scan...";

    socket.emit("start_scan", {
        target: target
    });
}

function stopScan(){

    socket.emit("stop_scan");

    document.getElementById("scan-status").innerHTML = "Status: Scan Stopped";
}

function downloadReport(){
    window.location.href = "/download_report";
}

socket.on("scan_output", function(msg){

    const terminal = document.getElementById("terminal");

    terminal.innerHTML += msg.data + "\n";

    terminal.scrollTop = terminal.scrollHeight;
});

socket.on("report_update", function(msg){

    const report = document.getElementById("report");

    report.innerHTML += msg.data + "<br>";

    report.scrollTop = report.scrollHeight;
});

socket.on("scan_complete", function(msg){

    document.getElementById("scan-status").innerHTML = "Status: Scan Completed";

    const terminal = document.getElementById("terminal");

    terminal.innerHTML += "\n\n[+] Scan Completed Successfully";
});