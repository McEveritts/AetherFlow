<div id="gemini-assistant-container" class="gemini-assistant hidden">
    <div class="gemini-header">
        <div class="gemini-title">
            <i class="fa fa-magic"></i> AetherFlow Assistant
            <span class="badge badge-success">AI Ultra Compatible</span>
        </div>
        <button id="close-gemini" class="btn btn-xs btn-transparent"><i class="fa fa-times"></i></button>
    </div>
    <div id="gemini-chat-history" class="gemini-body">
        <div class="chat-message assistant">
            <div class="message-content">
                Hello! I am your AetherFlow system assistant. How can I help you manage your server today?
            </div>
        </div>
    </div>
    <div class="gemini-input-area">
        <input type="text" id="gemini-input" placeholder="Ask about system stats, errors, or commands..." />
        <button id="gemini-send" class="btn btn-primary"><i class="fa fa-paper-plane"></i></button>
    </div>
</div>

<style>
    /* CSS will be moved to aetherflow.css later for better separation, but included here for now */
    .gemini-assistant {
        position: fixed;
        bottom: 20px;
        right: 20px;
        width: 350px;
        height: 500px;
        background: rgba(20, 20, 35, 0.95);
        backdrop-filter: blur(10px);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 12px;
        display: flex;
        flex-direction: column;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
        z-index: 9999;
        transition: transform 0.3s ease, opacity 0.3s ease;
    }

    .gemini-assistant.hidden {
        transform: translateY(20px);
        opacity: 0;
        pointer-events: none;
    }

    .gemini-header {
        padding: 15px;
        background: rgba(255, 255, 255, 0.05);
        border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        display: flex;
        justify-content: space-between;
        align-items: center;
        border-top-left-radius: 12px;
        border-top-right-radius: 12px;
    }

    .gemini-title {
        font-weight: 600;
        color: #fff;
        display: flex;
        align-items: center;
        gap: 8px;
    }

    .gemini-body {
        flex: 1;
        overflow-y: auto;
        padding: 15px;
        display: flex;
        flex-direction: column;
        gap: 10px;
    }

    .chat-message {
        display: flex;
        margin-bottom: 8px;
    }

    .chat-message.user {
        justify-content: flex-end;
    }

    .chat-message.assistant {
        justify-content: flex-start;
    }

    .message-content {
        max-width: 80%;
        padding: 10px 14px;
        border-radius: 12px;
        font-size: 0.9em;
        line-height: 1.4;
    }

    .chat-message.user .message-content {
        background: #007bff;
        color: white;
        border-bottom-right-radius: 2px;
    }

    .chat-message.assistant .message-content {
        background: rgba(255, 255, 255, 0.1);
        color: #ddd;
        border-bottom-left-radius: 2px;
    }

    .gemini-input-area {
        padding: 15px;
        border-top: 1px solid rgba(255, 255, 255, 0.1);
        display: flex;
        gap: 10px;
        background: rgba(0, 0, 0, 0.2);
        border-bottom-left-radius: 12px;
        border-bottom-right-radius: 12px;
    }

    #gemini-input {
        flex: 1;
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 20px;
        padding: 8px 15px;
        color: #fff;
        outline: none;
    }

    #gemini-input:focus {
        border-color: #007bff;
    }

    #gemini-send {
        border-radius: 50%;
        width: 36px;
        height: 36px;
        padding: 0;
        display: flex;
        align-items: center;
        justify-content: center;
    }
</style>