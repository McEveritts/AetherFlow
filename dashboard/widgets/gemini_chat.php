<div class="card card-main card-inverse">
    <div class="card-header">
        <h4 class="card-title">AetherFlow AI Assistant</h4>
    </div>
    <div class="card-body">
        <div id="gemini-chat-log" class="mb-3"
            style="height: 250px; overflow-y: auto; background-color: rgba(0,0,0,0.2); padding: 15px; border-radius: 4px; font-size: 13px;">
            <!-- Chat messages will be appended here -->
            <div class="text-muted mb-2"><em>Gemini: Hello! I'm your AetherFlow assistant. Ask me to check server
                    health, troubleshoot logs, or summarize usage.</em></div>
        </div>
        <div class="input-group">
            <input type="text" id="gemini-input" class="form-control" placeholder="Ask Gemini..." autocomplete="off">
            <button class="btn btn-primary" type="button" id="gemini-send">
                <i class="fa fa-paper-plane"></i>
            </button>
        </div>
    </div>
</div>

<script>
    $(document).ready(function () {
        function sendToGemini(prompt) {
            if (!prompt.trim()) return;

            // Append User Message
            $('#gemini-chat-log').append('<div class="mb-2 text-end"><span class="badge bg-primary rounded-pill text-wrap text-start" style="font-size: 13px; font-weight: normal; line-height: 1.5; padding: 8px 12px;">' + htmlspecialchars(prompt) + '</span></div>');
            $('#gemini-input').val('');
            $('#gemini-chat-log').scrollTop($('#gemini-chat-log')[0].scrollHeight);

            // Append Loading Indicator
            var loadingId = 'loading-' + Date.now();
            $('#gemini-chat-log').append('<div id="' + loadingId + '" class="mb-2 text-start"><span class="text-muted" style="font-size: 12px;"><i class="fa fa-spinner fa-spin"></i> Gemini is thinking...</span></div>');
            $('#gemini-chat-log').scrollTop($('#gemini-chat-log')[0].scrollHeight);

            $.ajax({
                url: 'api/gemini.php',
                method: 'POST',
                data: {
                    action: 'chat',
                    prompt: prompt,
                    csrf_token: $('meta[name="csrf-token"]').attr('content')
                },
                dataType: 'json',
                success: function (response) {
                    $('#' + loadingId).remove();
                    if (response.status === 'success') {
                        $('#gemini-chat-log').append('<div class="mb-2 text-start"><span class="badge bg-dark rounded-pill text-wrap text-start border border-secondary" style="font-size: 13px; font-weight: normal; line-height: 1.5; padding: 8px 12px;">' + response.reply + '</span></div>');
                    } else {
                        $('#gemini-chat-log').append('<div class="mb-2 text-start text-danger"><small><i class="fa fa-exclamation-triangle"></i> Error: ' + response.message + '</small></div>');
                    }
                    $('#gemini-chat-log').scrollTop($('#gemini-chat-log')[0].scrollHeight);
                },
                error: function () {
                    $('#' + loadingId).remove();
                    $('#gemini-chat-log').append('<div class="mb-2 text-start text-danger"><small><i class="fa fa-exclamation-triangle"></i> Communication error with Gemini API.</small></div>');
                    $('#gemini-chat-log').scrollTop($('#gemini-chat-log')[0].scrollHeight);
                }
            });
        }

        $('#gemini-send').click(function () {
            sendToGemini($('#gemini-input').val());
        });

        $('#gemini-input').keypress(function (e) {
            if (e.which == 13) {
                sendToGemini($(this).val());
                return false;
            }
        });

        function htmlspecialchars(str) {
            if (typeof (str) == "string") {
                str = str.replace(/&/g, "&amp;");
                str = str.replace(/"/g, "&quot;");
                str = str.replace(/'/g, "&#039;");
                str = str.replace(/</g, "&lt;");
                str = str.replace(/>/g, "&gt;");
            }
            return str;
        }
    });
</script>