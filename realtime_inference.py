import socket
import struct
import pandas as pd
import numpy as np
import joblib
import time
model = joblib.load('smartgrid_rf_model3.pkl')

feature_columns = joblib.load('feature_columns3.pkl')


UDP_IP = "0.0.0.0"
UDP_PORT = 5005

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

sock.bind((UDP_IP, UDP_PORT))

print("Listening for Simulink UDP packets...")

SEND_IP = "192.168.10.1"
SEND_PORT = 25000

send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)



raw_feature_names = [

'IED4_iA',
'IED4_iB',
'IED4_iC',

'MU1CurrentAngleA',
'MU1CurrentAngleB',
'MU1CurrentAngleC',

'MU1VoltageAngleA',
'MU1VoltageAngleB',
'MU1VoltageAngleC',

'MU2CurrentAngleA',
'MU2CurrentAngleB',
'MU2CurrentAngleC',

'MU2VoltageAngleA',
'MU2VoltageAngleB',
'MU2VoltageAngleC',

'MU3CurrentAngleA',
'MU3CurrentAngleB',
'MU3CurrentAngleC',

'MU3VoltageAngleA',
'MU3VoltageAngleB',
'MU3VoltageAngleC',

'MU4VoltageAngleA',
'MU4VoltageAngleB',
'MU4VoltageAngleC',

'consistency_1',
'consistency_2',
'consistency_3',

'frequencyMU1',
'frequencyMU2',
'frequencyMU3',
'frequencyMU4',

'threePhaseCMUA2',
'threePhaseCMUB2',
'threePhaseCMUC2',

'threePhaseCMUA3',
'threePhaseCMUB3',
'threePhaseCMUC3',

'threePhaseCMUA4',
'threePhaseCMUB4',
'threePhaseCMUC4',

'threePhaseCSum_1',
'threePhaseCSum_2',
'threePhaseCSum_3',

'threePhaseCMUA1',
'threePhaseCMUB1',
'threePhaseCMUC1',

'threePhaseVMUA1',
'threePhaseVMUB1',
'threePhaseVMUC1',

'threePhaseVMUA2',
'threePhaseVMUB2',
'threePhaseVMUC2',

'threePhaseVMUA3',
'threePhaseVMUB3',
'threePhaseVMUC3',

'threePhaseVMUA4',
'threePhaseVMUB4',
'threePhaseVMUC4',

'threePhaseVSum_1',
'threePhaseVSum_2',
'threePhaseVSum_3'

]

history_df = pd.DataFrame()
total_count = 0
attack_count = 0
healthy_count = 0
fault_count = 0
while True:
    total_count += 1
    
    data, addr = sock.recvfrom(4096)

    values = struct.unpack('61f', data)

    print("Received 61 values:")

    print(values)

    raw_df = pd.DataFrame(
    [values],
    columns=raw_feature_names
   )

# Rearrange columns EXACTLY like training
    raw_df = raw_df[feature_columns]

# Clean invalid values
    raw_df = raw_df.replace(
        [np.inf, -np.inf],
        np.nan
    )

    raw_df = raw_df.fillna(0)

    raw_df = raw_df.clip(
        lower=-1e6,
        upper=1e6
    )


    prediction = int(
        model.predict(raw_df)[0]
    )

    print("Sending prediction:", prediction)

    if prediction == 1:
        attack_count += 1

    elif prediction == 0:
        healthy_count += 1

    elif prediction == 2 and total_count > 4:
        fault_count += 1

    print("\n======================")
    print("Prediction:", prediction)

    print("Total Packets :", total_count)
    print("Attack Count  :", attack_count)
    print("Healthy Count :", healthy_count)
    print("Fault Count   :", fault_count)
    print("======================")
    if total_count > 4 :
        if prediction ==1 and total_count < 18 :
            p=struct.pack('i',0)
            send_sock.sendto(p,(SEND_IP , SEND_PORT))
        else:
            packet = struct.pack('i', prediction)
            send_sock.sendto(
                packet,
                (SEND_IP, SEND_PORT)
            )
