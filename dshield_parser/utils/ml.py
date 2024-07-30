import logging
import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.cluster import DBSCAN
from sklearn.decomposition import PCA
import matplotlib.pyplot as plt

def analyze_chunk(df, data, column_label, start, end, dbscan_minsamples=5, dbscan_eps=.5):
    output = f'Start: {start}\n'
    output += f'End: {end}\n'
    output += f"Data limit: {end}\n"
    output += f"Total data length: {len(df)}\n"
    output += f"DBScan Min Samples: {dbscan_minsamples}\n"
    output += f"DBScan EPS: {dbscan_eps}\n"
    if (end > len(df)):
        end = len(df) - 1  
    data = data[start:end]
    logging.info("Starting PCA fit.")
    pca = PCA(3)
    pca.fit(data)
    logging.info("Starting PCA transform.")
    reduced = pca.transform(data)
    dbscan = DBSCAN(eps=dbscan_eps, min_samples=dbscan_minsamples)
    logging.info("Starting DBSCAN fit.")
    dbscan.fit(reduced)
    y_labels = dbscan.labels_
    reduced_df = df[start:end]
    reduced_df['cluster'] = y_labels    
    output += f'Number of Clusters: {len(np.unique(y_labels))}\n\n'
    logging.info("creating text breakdown of output.")
    for cluster in np.unique(y_labels):
        output += str(f'Cluster {cluster}\n\n')
        output += f"Number of items in cluster: {len(reduced_df.loc[reduced_df['cluster'] == cluster])}"
        #output += str(df.iloc[reduced_df.loc[reduced_df['cluster'] == cluster].index[0]]) + "\n\n"
        if cluster == -1:
            pd.set_option('display.max_colwidth', None)
            output += "\n" + reduced_df[column_label].loc[reduced_df['cluster'] == cluster].to_string() + "\n"
        #    for index in range(len(reduced_df.loc[reduced_df['cluster'] == cluster].index)):
        #        output += str(df.iloc[reduced_df.loc[reduced_df['cluster'] == cluster].index[index],1]) + "\n"
        #else:
        #    output += str(df.iloc[reduced_df.loc[reduced_df['cluster'] == cluster].index[0],1]) + "\n"
        #output += "\n" + str(reduced_df.loc[reduced_df['cluster', 0] == cluster])
        else:
            pd.set_option('display.max_colwidth', None)
            output += "\n" + reduced_df[column_label].loc[reduced_df['cluster'] == cluster][:2].to_string() + "\n"
        #pd.set_option('display.max_colwidth', 40)
        pd.set_option('display.max_colwidth', None)
        output += "\n" + str(reduced_df.loc[reduced_df['cluster'] == cluster])
        output += "\n-----------------------------------------------------------------------\n\n"  
    #filehandle = open(f'{starttime}-{endtime}_clusters.txt', "w")
    #filehandle.write(output)
    #filehandle.close()
    logging.info("Returning summary text output and dataframe with results.")
    return(output, reduced_df)


def elbow_diagram(data, max_clusters=8, title=""):
    wcss = []
    for i in range(1, max_clusters):
        kmeans = KMeans(n_clusters=i, init="k-means++", max_iter=50, n_init=10)
        kmeans.fit(data)
        wcss.append(kmeans.inertia_)
    plt.plot(range(1, max_clusters), wcss)
    plt.title(f'The Elbow Method Graph ({title})')
    plt.xlabel('Number of clusters')
    plt.ylabel('WCSS')
    plt.show()