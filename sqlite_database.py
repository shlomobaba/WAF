import sqlite3
import time

FILE_NAME = "reverse_proxy_data_base.sqlite"


class DataBase:
    PacketsPerMinute = {}
    PacketsPerMinuteTracker = []
    def __init__(self):


        self.create_query("BannedIp",'"IP" TEXT,PRIMARY KEY("IP")')
        self.create_query("DangerLevel",'"IP" TEXT,"DangerLevel" INTEGER,PRIMARY KEY("IP")')
        self.create_query("PacketsPerMinute",'"IP" TEXT,"PPM" INTEGER,PRIMARY KEY("IP")')
        self.create_query("ppmTracker",'"IP" TEXT,"LastPPM" INTEGER,"RepAmount" INTEGER,PRIMARY KEY("IP")')

    def demo_table_check(self,tabel_name,col_names):
        values = ""
        for col_name in col_names:
                values+=col_name+" TEXT,"
        values = values[:-1]
        str_cols = ','.join(col for col in col_name)
        self.create_query(tabel_name,values)
        try:
            self.select_query(tabel_name,str_cols,"")
            return True
        except sqlite3.Error as e:
            return False

        self.drop_query(tabel_name)

    def create_query(self,tabel_name,values):
        connection = sqlite3.connect(FILE_NAME)
        db = connection.cursor()
        db.execute("CREATE TABLE IF NOT EXISTS "+tabel_name+"("+values+");")
        db.close()

    def select_query(self,tabel_name,rowNames,conditions):
        connection = sqlite3.connect(FILE_NAME)
        db = connection.cursor()
        if not conditions:
            db.execute("SELECT "+rowNames+" FROM "+tabel_name+";")
        else:
            res = db.execute("SELECT "+rowNames+" FROM "+tabel_name+" WHERE "+conditions+";")
            db.close()
            return  res.fetchall()
        db.close()

    def insert_query(self,tabel_name,values):
        connection = sqlite3.connect(FILE_NAME)
        db = connection.cursor()
        db.execute("INSERT INTO "+tabel_name+" VALUES("+values+");")
        db.close()

    def drop_query(self,tabel_name):
        connection = sqlite3.connect(FILE_NAME)
        db = connection.cursor()
        db.execute("DROP TABLE "+tabel_name+";")
        db.close()

    def update_query(self,tabel_name,col,value,ip):
        connection = sqlite3.connect(FILE_NAME)
        db = connection.cursor()
        db.execute("UPDATE "+tabel_name+" SET "+col+"="+value+" WHERE ip = "+ip+";")
        db.close()

    def delete_query(self,table_name,condition):
        connection = sqlite3.connect(FILE_NAME)
        db = connection.cursor()
        db.execute("DELETE FROM "+table_name+" WHERE "+condition+";")
        db.close()

    def delete_ppm_thread(self):
        db = DataBase()
        self.PacketsPerMinute = {}
        while True:
            found = False
            time.sleep(60)
            for ip in self.PacketsPerMinute:
                numberOfPackets = self.PacketsPerMinute[ip]
                for ppmHistory in self.PacketsPerMinuteTracker:
                    if ip in ppmHistory.values():
                        found = True
                        if ppmHistory["LastValue"] is numberOfPackets:
                            ppmHistory["RepAmount"] +=1
                            if ppmHistory["RepAmount"] > 10:
                                db.insert_query("BannedIp",ppmHistory["IP"])
                        else:
                            ppmHistory["LastValue"] = numberOfPackets
                            ppmHistory["RepAmount"] = 0
            if not found:
                self.PacketsPerMinuteTracker += {"IP" : ip , "LastValue" : numberOfPackets , "RepAmount" : 0}
            self.PacketsPerMinute ={}
