/*
 * MIT License
 *
 * Copyright (c) 2018 sruester
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <iostream>
#include <ClientSocket.h>
#include <SSLClient.h>
#include <queue>
#include <fstream>
#include <sstream>
#include <Thread.h>

using namespace std;

pthread_mutex_t stack_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t print_lock = PTHREAD_MUTEX_INITIALIZER;
queue<std::string> hosts;


void do_connect(std::string host, unsigned short port, std::string ciphers, std::string curves, std::string &result)
{
    SSLClient cs(host, port);
    cs.RestrictCipherSuites(ciphers);
    cs.RestrictECCurves(curves);

    if(!cs.Open())
    {
        switch(cs.GetLastError())
        {
        case SSLClient::ERR_TCP_CONNECT_FAILED:
            result = "tcp_connect_failed"; break;
        case SSLClient::ERR_CONNECTTION_SHUTDOWN:
            result = "ssl_shutdown" ; break;
        case SSLClient::ERR_CONNECTTION_TERMINATED:
            result = "ssl_terminated"; break;
        default:
            result = "error";
        }
    }
    else
    {
        result = cs.GetCurrentCipherName() + "," + cs.GetKeyExchangeMethod();
    }

}

void *thread_func(void *param)
{
    std::string host;
    static int cnt = 1;
    int current_pos;

    while(!hosts.empty())
    {
        pthread_mutex_lock(&stack_lock);
            if(hosts.empty())
            {
                pthread_mutex_unlock(&stack_lock);
                return NULL;
            }
            host = hosts.front();
            hosts.pop();
            current_pos = cnt++;
        pthread_mutex_unlock(&stack_lock);

        {
            std::stringstream ss;

            std::string result = "unknown";

            do_connect(host, 443, "ECDHE", "X25519",       result);
            ss << current_pos << ";support;" << host << ";" << result << std::endl;

            do_connect(host, 443, "ECDHE", "P-256:X25519", result);
            ss << current_pos << ";preferred;" << host << ";" << result << std::endl;

            pthread_mutex_lock(&print_lock);
                std::cout << ss.str();
            pthread_mutex_unlock(&print_lock);
        }

    }
    return NULL;
}

int main()
{
    std::ifstream hostlist("/tmp/hostlist");
    std::string line;
    while(std::getline(hostlist, line))
    {
        hosts.push(line);
    }

    const int thread_count = 30;
    Thread *threads[thread_count];

    for(int i = 0; i < thread_count; i++)
    {
        threads[i] = new Thread(&thread_func);
        threads[i]->Start(NULL);
    }

    for(int i = 0; i < thread_count; i++)
    {
        threads[i]->Join();
        delete threads[i];
    }

    return 0;
}
