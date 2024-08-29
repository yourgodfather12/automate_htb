document.addEventListener('DOMContentLoaded', function () {
    const socket = io.connect(window.location.origin);
    const scanForm = document.getElementById('scanForm');
    const scanProgress = document.getElementById('scanProgress');
    const progressBar = scanProgress.querySelector('.progress-bar');

    // WebSocket events
    socket.on('scan_update', debounce(function(data) {
        updateProgressBar();
        toastr.info(data.message);
    }, 300));

    socket.on('scan_complete', function(data) {
        if (data.status === 'completed') {
            toastr.success('Scan completed successfully!');
            fetchResults(data.target);
        } else {
            toastr.error('Scan failed!');
        }
        resetProgressBar();
    });

    // Form submit event
    scanForm.addEventListener('submit', function (e) {
        e.preventDefault();
        const form = e.target;
        const targetInput = form.querySelector('input[name="target"]');
        const pattern = /^((\d{1,3}\.){3}\d{1,3}|([a-zA-Z0-9]+\.)+[a-zA-Z]{2,})$/;

        if (!pattern.test(targetInput.value)) {
            toastr.error('Invalid IP address or domain name');
            return;
        }

        fetch(form.action, {
            method: 'POST',
            body: new URLSearchParams(new FormData(form))
        }).then(response => response.json())
          .then(data => {
            if (data.status === 'started') {
                toastr.info('Scan started...');
                scanProgress.style.display = 'block';
                progressBar.style.width = '0%';
            }
          }).catch(error => {
            toastr.error('Failed to start scan.');
        });
    });

    function fetchResults(target) {
        fetch(`/results/${target}`)
            .then(response => response.json())
            .then(data => {
                document.getElementById('openPortsContent').innerText = JSON.stringify(data.open_ports, null, 2);
                document.getElementById('vulnerabilitiesContent').innerText = JSON.stringify(data.vulnerabilities, null, 2);
                updateChart(data);  // Function to update the Chart.js graph
            }).catch(error => {
                toastr.error('Failed to fetch results.');
        });
    }

    function updateProgressBar() {
        let currentWidth = parseFloat(progressBar.style.width);
        if (currentWidth < 100) {
            progressBar.style.width = (currentWidth + 20) + '%';
        }
    }

    function resetProgressBar() {
        progressBar.style.width = '100%';
        setTimeout(() => {
            scanProgress.style.display = 'none';
        }, 1000);
    }

    function updateChart(data) {
        const ctx = document.getElementById('scanChart').getContext('2d');
        const chartData = {
            labels: Object.keys(data.open_ports),  // Assuming open_ports data is a key-value structure
            datasets: [{
                label: 'Open Ports',
                data: Object.values(data.open_ports),
                backgroundColor: 'rgba(0, 123, 255, 0.5)',
                borderColor: 'rgba(0, 123, 255, 1)',
                borderWidth: 1
            }]
        };

        new Chart(ctx, {
            type: 'bar',
            data: chartData,
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }

    // Utility: Debounce function to limit rapid calls
    function debounce(func, wait) {
        let timeout;
        return function(...args) {
            const context = this;
            clearTimeout(timeout);
            timeout = setTimeout(() => func.apply(context, args), wait);
        };
    }
});
