import streamlit as st
import requests
import json

# Azure ML Web Service Scoring URI
scoring_uri = "http://34c536ce-86a6-444b-a449-c208563a365e.eastus2.azurecontainer.io/score"  

# Set up headers for HTTP request
headers = {'Content-Type': 'application/json'}

# Mapping for label encoding of categorical variables
protocol_mapping = {'tcp': 1, 'udp': 0, 'icmp': 2}
service_mapping = {'http': 0, 'ftp': 1, 'smtp': 2, 'other': 3}  # Add other services if needed
flag_mapping = {'SF': 1, 'S0': 0, 'REJ': 2, 'RSTR': 3, 'RSTO': 4}  # Add other flags if needed

# Streamlit app header
st.markdown("""
    <style>
        h1 { color: #008080; text-align: center; }
        div.stButton > button { 
            border: none;
            padding: 10px 20px;
            background-color: #5cb85c;
            color: white;
            font-size: 18px;
            border-radius: 8px;
            margin: 0 auto;
            display: block;
        }
    </style>
""", unsafe_allow_html=True)

st.title("🚀 Intrusion Detection System")
st.markdown("### Predict the likelihood of an **Intrusion** with minimal input.")

# Display form for main feature inputs
st.markdown("#### Enter the key feature values:")
with st.form(key="intrusion_form"):
    # Main features for input
    duration = st.slider("Duration (ms)", min_value=0, max_value=1000, value=50, help="Duration of the connection in ms")
    src_bytes = st.number_input("Source Bytes", min_value=0, value=0, step=100, help="Bytes sent from source to destination")
    dst_bytes = st.number_input("Destination Bytes", min_value=0, value=0, step=100, help="Bytes sent from destination to source")
    wrong_fragment = st.selectbox("Wrong Fragment", [0, 1, 2, 3], help="Indicates the number of wrong fragments")

    # Dropdowns for categorical features with encoding
    protocol_type = st.selectbox("Protocol Type", list(protocol_mapping.keys()), help="Type of protocol used")
    service = st.selectbox("Service", list(service_mapping.keys()), help="Service being accessed")
    flag = st.selectbox("Flag", list(flag_mapping.keys()), help="Connection state flag")

    # Submit button
    submit_button = st.form_submit_button(label="🚨 Predict Intrusion 🚨")

# Only run the prediction when the submit button is clicked
if submit_button:
    # Convert categorical inputs to their encoded values
    protocol_encoded = protocol_mapping[protocol_type]
    service_encoded = service_mapping[service]
    flag_encoded = flag_mapping[flag]

    # Prepare input data according to required format
    input_data = [
        duration, protocol_encoded, service_encoded, flag_encoded, src_bytes, dst_bytes,
        0, wrong_fragment, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 3,
        0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 100, 100, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0
    ]

    # Convert the input data to a JSON string
    input_data_json = json.dumps({"data": [input_data]})
    
    # Send HTTP POST request to Azure ML web service
    response = requests.post(scoring_uri, data=input_data_json, headers=headers)
    # Process the response
    if response.status_code == 200:
        result = json.loads(response.json())
        result = result["result"][0]

        if result == 0:
            st.success("Prediction: **Normal** ✅")
        else:
            st.error("Prediction: **Intrusion Detected** 🚨")
    else:
        st.error(f"Error: {response.status_code}")
        st.write(response.text)
