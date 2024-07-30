import logging
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

#def plot_date_counts(dict):
#    lists = sorted(dict.items())
#    x, y = zip(*lists)


    #plt.locator_params(axis='y', nticks=4)
    #plt.locator_params(axis='x', nticks=8)
#    plt.ticklabel_format(style='plain')     
#    plt.plot(x, y)
#    plt.xticks(get_ticks(x, 8))
#    plt.ylabel("Number of Access Attempts")
#    plt.xlabel("Date")
#    plt.title("Honeypot Traffic Over Time")
#    plt.show()

def get_ticks(values, numticks):
    ticks = []
    length = len(values)
    ticks.append(values[0])
    separation = int((length) / (numticks -1))
    counter = separation
    while counter < (length -1):
        ticks.append(values[counter])
        counter += separation
    if len(ticks) < numticks:
        ticks.append(values[length-1])
    return ticks

def plot_date_counts(data, main_title, y_label):
    if len(data) > 1:
        num_rows = (len(data) // 2) + (len(data) % 2)
        num_columns = (len(data) // num_rows) + (len(data) % 2)
        figure, subplots = plt.subplots(num_rows, num_columns, figsize=(20,12), constrained_layout=True)
    else:
        figure, subplots = plt.subplots(figsize=(10,6), constrained_layout=True)

    plots = subplots.flatten()

    #overlapping_figure, overlapping_plot = plt.subplots(figsize=(20,12), constrained_layout=True)
    #overlapping_plot.set_ylabel(y_label)
    #overlapping_plot.set_xlabel("Date")
    #overlapping_plot.set_title(main_title)

    plot_index = 0

    figure.suptitle(main_title)

    for honeypotname, honeypot_data in data.items():
        if len(honeypot_data) == 0:
            logging.info("Blank data received for {honeypotname}")
            logging.info("Will ignore plotting graph data for {honeypotname}")
        else:
            lists = sorted(honeypot_data.items())
            x, y = zip(*lists)

            if len(data) == 1:
                subplots.xaxis.set_major_locator(plt.MaxNLocator(8))
                subplots.ticklabel_format(style='plain')     
                subplots.plot(x, y)
                subplots.set_ylabel(y_label)
                subplots.set_xlabel("Date")
                subplots.set_title(honeypotname)                
            else:
                plots[plot_index].xaxis.set_major_locator(plt.MaxNLocator(8))
                #ax.ticklabel_format(style='plain')     
                plots[plot_index].plot(x, y)
                #ax.plot([1, 2, 3], label='Inline label')
                #line.set_label('Label via method')
                #ax.legend()
                #overlapping_plot.plot(x, y, label=honeypotname)
                plots[plot_index].set_ylabel(y_label)
                plots[plot_index].set_xlabel("Date")
                plots[plot_index].set_title(honeypotname)
        plot_index += 1

    #plt.show()
    plt.tight_layout()
    plt.savefig(f'{main_title.replace(" ","_")}_multi.png')


    #overlapping_plot.legend()
    #overlapping_plot.plt.savefig(f'{main_title.replace(" ","_")}_overlap.png')

def plot_date_counts_overlapping(data, main_title, y_label):
    overlapping_figure, overlapping_plot = plt.subplots(figsize=(20,12), constrained_layout=True)
    overlapping_plot.set_ylabel(y_label)
    overlapping_plot.set_xlabel("Date")
    overlapping_plot.set_title(main_title)
    for honeypotname, honeypot_data in data.items():
        if len(honeypot_data) == 0:
            logging.info("Blank data received for {honeypotname}")
            logging.info("Will ignore plotting graph data for {honeypotname}")
        else:
            lists = sorted(honeypot_data.items())
            x, y = zip(*lists)
            overlapping_plot.plot(x, y, label=honeypotname)
    overlapping_plot.legend()
    overlapping_plot.xaxis.set_major_locator(plt.MaxNLocator(8))
    plt.tight_layout()
    plt.savefig(f'{main_title.replace(" ","_")}_overlapping.png')

def plot_time_counts(dict, plottype=None, ylabel=None, xlabel=None, title=None, type=None):
    lists = sorted(dict.items())
    x, y = zip(*lists)
    start = x[0]
    end = x[-1]  
    #daterange = pd.timedelta_range(start, end)  

    plt.ticklabel_format(style='plain')     
    plt.hist(x, y)
    #plt.xticks(daterange)
    plt.ylabel("Number of Access Attempts")
    plt.xlabel("Date")
    plt.title("Honeypot Traffic Over Time")
    plt.show()
    