document.addEventListener('DOMContentLoaded', () => {
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    const analyzeBtn = document.getElementById('analyze-btn');
    const errorMessage = document.getElementById('error-message');
    const loadingSection = document.getElementById('loading-section');
    const reportSection = document.getElementById('report-section');
    
    // State
    let selectedFile = null;

    // Prevent default drag behaviors
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, preventDefaults, false);
        document.body.addEventListener(eventName, preventDefaults, false);
    });

    // Toggle dropzone visual cues
    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, highlight, false);
    });
    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, unhighlight, false);
    });

    // Handle dropped files
    dropZone.addEventListener('drop', handleDrop, false);

    // Handle click to browse
    dropZone.addEventListener('click', () => {
        fileInput.click();
    });

    // Handle browse selection
    fileInput.addEventListener('change', handleFileSelect, false);

    // Handle analyze click
    analyzeBtn.addEventListener('click', uploadAndAnalyze);

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    function highlight() {
        dropZone.classList.add('dragover');
    }

    function unhighlight() {
        dropZone.classList.remove('dragover');
    }

    function handleDrop(e) {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files && files.length > 0) {
            processFile(files[0]);
        }
    }

    function handleFileSelect(e) {
        const files = e.target.files;
        if (files && files.length > 0) {
            processFile(files[0]);
        }
    }

    function processFile(file) {
        errorMessage.classList.add('hidden');
        errorMessage.textContent = '';
        
        // Validate format
        const valName = file.name.toLowerCase();
        if (!(valName.endsWith('.png') || valName.endsWith('.jpg') || valName.endsWith('.jpeg'))) {
            showError("Unsupported file type. Please select a PNG, JPG, or JPEG image.");
            resetFileState();
            return;
        }

        // Under 16MB
        if (file.size > 16 * 1024 * 1024) {
            showError("File size exceeds 16MB limit. Please upload a smaller image.");
            resetFileState();
            return;
        }

        selectedFile = file;
        
        // Update UI to show selected file name
        const uploadPrompt = dropZone.querySelector('.upload-prompt');
        uploadPrompt.innerHTML = `Selected: <span class="mono" style="font-weight:600; color:var(--accent);">${file.name}</span>`;
        
        analyzeBtn.disabled = false;
    }

    function resetFileState() {
        selectedFile = null;
        fileInput.value = '';
        analyzeBtn.disabled = true;
        const uploadPrompt = dropZone.querySelector('.upload-prompt');
        uploadPrompt.innerHTML = `Drag & drop your image here, or <span class="browse-link">browse</span>`;
    }

    function showError(msg) {
        errorMessage.textContent = msg;
        errorMessage.classList.remove('hidden');
    }

    function uploadAndAnalyze() {
        if (!selectedFile) return;

        // Reset display states
        errorMessage.classList.add('hidden');
        reportSection.classList.add('hidden');
        loadingSection.classList.remove('hidden');
        analyzeBtn.disabled = true;

        const formData = new FormData();
        formData.append('image', selectedFile);

        fetch('/analyze', {
            method: 'POST',
            body: formData
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(errData => {
                    throw new Error(errData.error || "Server error while analyzing image.");
                });
            }
            return response.json();
        })
        .then(data => {
            loadingSection.classList.add('hidden');
            analyzeBtn.disabled = false;
            
            if (data.success) {
                renderReport(data);
            } else {
                showError(data.error || "Analysis failed.");
            }
        })
        .catch(err => {
            loadingSection.classList.add('hidden');
            analyzeBtn.disabled = false;
            showError(err.message || "A network error occurred while uploading.");
        });
    }

    function renderReport(data) {
        // 1. Verdict & Summary Card
        const verdictCard = document.getElementById('verdict-card');
        const verdictBadge = document.getElementById('report-verdict-badge');
        const reasonsList = document.getElementById('verdict-reasons-list');
        
        // Reset classes
        verdictCard.className = 'card verdict-card span-full';
        
        if (data.verdict === 'SUSPICIOUS') {
            verdictCard.classList.add('suspicious');
            verdictBadge.textContent = 'SUSPICIOUS';
        } else {
            verdictCard.classList.add('clean');
            verdictBadge.textContent = 'CLEAN';
        }

        // Render reasons list
        reasonsList.innerHTML = '';
        data.reasons.forEach(reason => {
            const li = document.createElement('li');
            li.textContent = reason;
            reasonsList.appendChild(li);
        });

        // 2. Analysis Status
        document.getElementById('status-filename').textContent = data.metadata.filename;
        document.getElementById('status-filename').title = data.metadata.filename;
        document.getElementById('status-colormode').textContent = `${data.metadata.mode} (${data.metadata.format})`;
        document.getElementById('status-resolution').textContent = data.metadata.dimensions;
        
        // 3. Metadata Inspection
        const exifStatus = document.getElementById('metadata-exif-status');
        const chunksStatus = document.getElementById('metadata-chunks-status');
        const exifDetailBox = document.getElementById('exif-detail-box');
        const exifTableBody = document.querySelector('#exif-table tbody');
        
        exifTableBody.innerHTML = '';
        
        if (data.metadata.has_exif) {
            exifStatus.textContent = `${Object.keys(data.metadata.exif).length} Tags Found`;
            exifStatus.className = 'status-value success';
            exifDetailBox.classList.remove('hidden');
            
            // Populate Exif Table
            Object.entries(data.metadata.exif).forEach(([tag, val]) => {
                const tr = document.createElement('tr');
                const tdTag = document.createElement('td');
                tdTag.textContent = tag;
                const tdVal = document.createElement('td');
                tdVal.textContent = val;
                tr.appendChild(tdTag);
                tr.appendChild(tdVal);
                exifTableBody.appendChild(tr);
            });
        } else {
            exifStatus.textContent = 'None Found';
            exifStatus.className = 'status-value';
            exifDetailBox.classList.add('hidden');
        }

        if (data.metadata.has_text_chunks) {
            const keys = Object.keys(data.metadata.text_chunks).join(', ');
            chunksStatus.textContent = `Found Keys: ${keys}`;
        } else {
            chunksStatus.textContent = 'None Found';
        }

        // 4. EOF Extra Appended Bytes Check
        const eofDetailsBox = document.getElementById('eof-details-box');
        const eofBytesCount = document.getElementById('eof-bytes-count');
        const eofPreviewText = document.getElementById('eof-preview-text');

        if (data.eof_analysis.detected) {
            eofDetailsBox.classList.remove('hidden');
            eofBytesCount.textContent = data.eof_analysis.extra_bytes;
            
            if (data.eof_analysis.preview) {
                eofPreviewText.textContent = data.eof_analysis.preview;
            } else {
                eofPreviewText.textContent = "[Binary Data - Non-printable characters]";
            }
        } else {
            eofDetailsBox.classList.add('hidden');
        }

        // 5. LSB Analysis Progress and Text
        const channels = ['red', 'green', 'blue'];
        channels.forEach(ch => {
            const info = data.lsb_analysis[ch];
            const entId = `lsb-${ch}-entropy`;
            const barId = `lsb-${ch}-bar`;
            const ratioId = `lsb-${ch}-ratio`;
            
            document.getElementById(entId).textContent = info.entropy.toFixed(4);
            document.getElementById(ratioId).textContent = info.ratio.toFixed(4);
            
            // Calculate progress bar width based on max Shannon entropy of 8.0
            const percentage = (info.entropy / 8.0) * 100;
            document.getElementById(barId).style.width = `${percentage}%`;
        });

        // 6. Chi-Square Analysis Progress and Text
        channels.forEach(ch => {
            const info = data.chi_analysis[ch];
            const statId = `chi-${ch}-stat`;
            const barId = `chi-${ch}-bar`;
            const pId = `chi-${ch}-p`;
            
            document.getElementById(statId).textContent = `${info.chi_square.toFixed(2)} (dof: ${info.dof})`;
            document.getElementById(pId).textContent = info.p_value.toFixed(4);
            
            // Calculate progress bar width based on stego probability (0.0 to 1.0)
            const percentage = info.p_value * 100;
            document.getElementById(barId).style.width = `${percentage}%`;
        });

        // Finally, make the report visible
        reportSection.classList.remove('hidden');
        
        // Scroll report into view smoothly (using default browser instant behavior to obey 'no animation' rules if strictly strict, but standard scrollIntoView is functional)
        reportSection.scrollIntoView({ behavior: 'auto' });
    }
});
