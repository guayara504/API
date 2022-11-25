import msvcrt
import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import accuracy_score
from keras.models import Sequential
from keras.layers import Dense
from keras.wrappers.scikit_learn import KerasClassifier
import time


def visualizar(archivo):
            with open(archivo, 'r') as f:
                print(f.read())



def creacion_Dataset():
    
    cols ="""duration,protocol_type,service,flag,src_bytes,dst_bytes,land,wrong_fragment,urgent,hot,num_failed_logins,logged_in,num_compromised,root_shell,su_attempted,
    num_root,num_file_creations,num_shells,num_access_files,num_outbound_cmds,is_host_login,is_guest_login,count,srv_count,serror_rate,srv_serror_rate,rerror_rate,
    srv_rerror_rate,same_srv_rate,diff_srv_rate,srv_diff_host_rate,dst_host_count,dst_host_srv_count,dst_host_same_srv_rate,dst_host_diff_srv_rate,
    dst_host_same_src_port_rate,dst_host_srv_diff_host_rate,dst_host_serror_rate,dst_host_srv_serror_rate,dst_host_rerror_rate,dst_host_srv_rerror_rate"""
    columns =[]
    for c in cols.split(','):
        if(c.strip()):
            columns.appfinal(c.strip())
    columns.appfinal('target')
    
    
    attacks_types = {'normal': 'normal','back': 'dos','buffer_overflow': 'u2r','ftp_write': 'r2l','guess_passwd': 'r2l','imap': 'r2l','ipsweep': 'probe','land': 'dos',
    'loadmodule': 'u2r','multihop': 'r2l','neptune': 'dos','nmap': 'probe','perl': 'u2r','phf': 'r2l','pod': 'dos','portsweep': 'probe','rootkit': 'u2r','satan': 'probe',
    'smurf': 'dos','spy': 'r2l','teardrop': 'dos','warezclient': 'r2l','warezmaster': 'r2l',
    }
    df = pd.read_csv(MuestraData, names = columns)
    df['Attack Type'] = df.target.apply(lambda r:attacks_types[r[:-1]])
    print(df.head)
    print(df.shape)
    print(df.isnull().sum())

    num_cols = df._get_numeric_data().columns
  
    cate_cols = list(set(df.columns)-set(num_cols))
    cate_cols.remove('target')
    cate_cols.remove('Attack Type')
    
    def bar_graph(feature):
        df[feature].value_counts().plot(kind="bar")

    bar_graph("protocol_type")
    plt.show()   
    bar_graph('logged_in')
    plt.show() 
    bar_graph("service")
    plt.show()    
    bar_graph('target')
    plt.show() 
    bar_graph('Attack Type')
    plt.show()

    df = df.dropna('columns')

    df = df[[col for col in df if df[col].nunique() > 1]]

    corr = df.corr()

    plt.figure(figsize=(15,12))

    sns.heatmap(corr)

    plt.show()


    df.drop('num_root',axis = 1,inplace = True)

    df.drop('srv_serror_rate',axis = 1,inplace = True)

    df.drop('srv_rerror_rate',axis = 1, inplace=True)

    df.drop('dst_host_srv_serror_rate',axis = 1, inplace=True)

    df.drop('dst_host_serror_rate',axis = 1, inplace=True)

    df.drop('dst_host_rerror_rate',axis = 1, inplace=True)

    df.drop('dst_host_srv_rerror_rate',axis = 1, inplace=True)

    df.drop('dst_host_same_srv_rate',axis = 1, inplace=True)

    df_std = df.std()
    df_std = df_std.sort_values(ascfinaling = True)

    pmap = {'icmp':0,'tcp':1,'udp':2}
    df['protocol_type'] = df['protocol_type'].map(pmap)
    

    fmap = {'SF':0,'S0':1,'REJ':2,'RSTR':3,'RSTO':4,'SH':5 ,'S1':6 ,'S2':7,'RSTOS0':8,'S3':9 ,'OTH':10}
    df['flag'] = df['flag'].map(fmap)

    df.drop('service',axis = 1,inplace= True)

    df = df.drop(['target',], axis=1)
    print(df.shape)

    Y = df[['Attack Type']]
    X = df.drop(['Attack Type',], axis=1)

    sc = MinMaxScaler()
    X = sc.fit_transform(X)

    X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.33, random_state=42)
    print(X_train.shape, X_test.shape)
    print(Y_train.shape, Y_test.shape)

    def fun():
        model = Sequential()
        
        #here 30 is output dimension
        model.add(Dense(30,input_dim =30,activation = 'relu',kernel_initializer='random_uniform'))
        
        #in next layer we do not specify the input_dim as the model is sequential so output of previous layer is input to next layer
        model.add(Dense(1,activation='sigmoid',kernel_initializer='random_uniform'))
        
        #5 classes-normal,dos,probe,r2l,u2r
        model.add(Dense(5,activation='softmax'))
        
        #loss is categorical_crossentropy which specifies that we have multiple classes
        
        model.compile(loss ='categorical_crossentropy',optimizer = 'adam',metrics = ['accuracy'])
        
        return model

    modelo = KerasClassifier(build_fn=fun,epochs=100,batch_size=64)
    
    inicio = time.time()
    modelo.fit(X_train, Y_train.values.ravel())
    final = time.time()

    print('Training time')
    print((final-inicio))

    inicio_time = time.time()
    Y_test_pred = modelo.predict(X_test)
    tiempo_total = time.time()

    print("Tiempo del Test: ",tiempo_total-inicio_time)

    inicio_time = time.time()
    Y_train_pred = modelo.predict(X_train)
    tiempo_total = time.time()

    accuracy_score(Y_train,Y_train_pred)

    accuracy_score(Y_test,Y_test_pred)


if __name__ == "__main__":

    MuestraData = "dataset\\kddcup.data_10_percent_corrected"
    NombresValores = "dataset\\kddcup.names"
    TiposAtaques = "dataset\\training_attack_types"
    os.system ("cls")
    visualizarDataset = input("¿Visualizar datos?\n1.Si\n2.No\nIngrese: ")
    os.system ("cls")
    if(visualizarDataset == "1"):
        condicion = 1
        while condicion == 1:
            archivo = None
            numero = input("Visualizar:\n1.10% Dataset\n2.Nombres Valores\n3.Tipos de ataques\nIngrese: ")
            os.system ("cls")
            if numero == "1": archivo = MuestraData
            elif numero == "2": archivo = NombresValores
            elif numero == "3": archivo = TiposAtaques
            visualizar(archivo)
            condicion =int(input("\n1.Reiniciar\n2.Cerrar\nIngrese: "))
            os.system ("cls")
    
    creacion_Dataset()


    print("\nPULSE UNA TECLA PARA CERRAR...")
    msvcrt.getch()