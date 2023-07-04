# Project5

## 默克尔树简介

Merkle Tree（默克尔树）又名哈希树，在Merkle Tree中，每个节点都标有一个数据块的加密哈希值。Merkle Tree可以用来验证任何一种在计算机中和计算机之间存储、处理和传输的数据。它们可以确保在点对点网络中数据传输的速度不受影响，数据跨越自由的通过任意媒介，且没有损坏，也没有改变。
Merkel Tree是Bitcoin的核心组件,在Bitcoin的白皮书中得知，Merkle Trees的引入是将一个区块中所有的交易进行整合生成然后整个交易集合的数字指纹，从而确保的BTC不可篡改性。

## 默克尔树的实现

Merkel树的实现原理如图，和哈希列表一样，把数据分成小的数据块，最下面的叶节点包含存储数据或其哈希值，非叶子节点（包括中间节点和根节点）都是它两个孩子节点内容的hash值。

![image](https://github.com/1-14/Project5/blob/main/3.png)

```
#向上逐步迭代生成merkel树
def generate_Tree(blocks):
    depth = math.ceil(math.log2(len(blocks)+1))
    #The depth of the tree.
    Treenode = [[hashlib.sha256(('0x00'+data).encode()).hexdigest() for data in blocks]]
    assert Treenode[0][-1] != Treenode[0][-2]
    #对最后两个元素进行检测，是否是篡改以后相等
    #将每一个元素进行hash运算
    for i in range(depth):
        lay_number = len(Treenode[i]) #每一层的个数
        #print(lay_number)
        Treenode.append([hashlib.sha256(('0x01'+Treenode[i][j*2]).encode()+('0x01'+Treenode[i][j*2+1]).encode()).hexdigest() for j in range(int(lay_number/2))])
        if lay_number%2!=0:
            Treenode[i+1].append(Treenode[i][-1]) 
    
    return Treenode
```

## 默克尔树的存在性证明

![image](https://github.com/1-14/Project5/blob/main/1.png)  

参考链接：https://blog.csdn.net/shangsongwww/article/details/85339243

存在性证明的第一步就是解析merkle block message。所以我们先看一下SPV节点接收到的merkle block message：

摘自[Bitcoin Developer Reference 的 Merkle Block Message部分](https://bitcoin.org/en/developer-reference#mempool)

```
The merkleblock message is a reply to a getdata message which requested a block using the inventory type MSG_MERKLEBLOCK. It is only part of the reply: if any matching transactions are found, they will be sent separately as tx messages.
If a filter has been previously set with the filterload message, the merkleblock message will contain the TXIDs of any transactions in the requested block that matched the filter, as well as any parts of the block’s merkle tree necessary to connect those transactions to the block header’s merkle root. The message also contains a complete copy of the block header to allow the client to hash it and confirm its proof of work.
```

解析之后 结果如下：

```
01000000 ........................... Block version: 1
82bb869cf3a793432a66e826e05a6fc3
7469f8efb7421dc88067010000000000 ... Hash of previous block's header
7f16c5962e8bd963659c793ce370d95f
093bc7e367117b3c30c1f8fdd0d97287 ... Merkle root
76381b4d ........................... Time: 1293629558
4c86041b ........................... nBits: 0x04864c * 256**(0x1b-3)
554b8529 ........................... Nonce
07000000 ........................... Transaction count: 7
04 ................................. Hash count: 4
3612262624047ee87660be1a707519a4
43b1c1ce3d248cbfc6c15870f6c5daa2 ... Hash #1
019f5b01d4195ecbc9398fbf3c3b1fa9
bb3183301d7a1fb3bd174fcfa40a2b65 ... Hash #2
41ed70551dd7e841883ab8f0b16bf041
76b7d1480e4f0af9f3d4c3595768d068 ... Hash #3
20d2a7bc994987302e5b1ac80fc425fe
25f8b63169ea78e68fbaaefa59379bbf ... Hash #4
01 ................................. Flag bytes: 1
1d ................................. Flags: 1 0 1 1 1 0 0 0
```

Mercle Block Message包含，块头全部信息，交易个数，以及用于生成Merkle Proof的Hash值列表和Flag值列表。

接下来SPV可以根据交易个数得出 Merkle Tree的大小（不用真正意义上的建立一个MerkleTree，而是通过Merkle Tree 的SIZE 从而推导出 Merkle Path里节点间联系），根据Hash列表以及 Flags列表确定目标交易及它到Merkle Root的路径。

最后如何衡量我们指定的Block都是否包含目标交易？有以下条件：

```
if you find a node whose left and right children both have the same hash, fail. This is related to CVE-2012-2459.
If you run out of flags or hashes before that condition is reached, fail. Then perform the following checks (order doesn’t matter):
```
可以分成两个阶段，在构建过程中：

如果某个Node的左右节点的hash相同，则返回 fail；

简单来说：为了防止重复交易设置的，spv会去检查最后两个节点的hash值是否相同，如果相同则返回错误。具体解释可以参考博士论文：on the application of hash function in bitcoin

之前有过一个存疑点：全节点在构建merkle tree的时候，对待“落单”的节点会copy然后以MerkleBlockMessage发过来，这种情况会不会与上述的判断条件矛盾？  
回答：不会，主要原因：交易总数限制着。具体在不存在性证明部分进行解释（涉及全节点生成MerkleBlockMessage逻辑）。  
如果在还没能得出Merkle Root的情况下，Flag或者Hash已使用完，则返回 fail。  
构建完毕之后：  
如果hash列表中还有没有使用到的hash值，返回 fail；  
如果flag列表中还有没有使用到的flag值，返回 fail，除非为了满足最低flag个数标准从而填充的0；  
本地生成的Merkle root用于和块头中的Merkle root不相同，返回 fail；  
如果块头不合法（PoW的值大于Target），返回 fail；

python实现代码

```
def Inclusion_Proof(element,Treenode):
    value = (hashlib.sha256(('0x00'+element).encode())).hexdigest()
    #判断是不是一个单独的数据块
    depth = len(Treenode)
    path = []
    if value in Treenode[0]:
        index = Treenode[0].index(value)
    else:
        print("The element not in the merkle tree.")
        return
    #print(depth-1)
    for i in range(depth):
        if index%2 ==  0:
            if index+1 != len(Treenode[i]):
                path.append(['left',Treenode[i][index+1]])
            #将这个值放入merkel树
        else:
            path.append(['right',Treenode[i][index-1]])
        index = int(index/2)
    #这里应该注意hash拼接的顺序
    for w in path:
        if w[0] == 'left':
            value = hashlib.sha256(('0x01'+value).encode()+('0x01'+w[1]).encode()).hexdigest()
        else:
            value = hashlib.sha256(('0x01'+w[1]).encode()+('0x01'+value).encode()).hexdigest()
    #print(Treenode[depth-1][0])
    if value == Treenode[depth-1][0]:
        print("Inclusion proof correct.")
    else:
        print("Inclusion proof false.")
```

## 默克尔树的不存在性证明

![image](https://github.com/1-14/Project5/blob/main/2.png)

参考链接 [Sorted merkle tree as solution to issue #693](https://gist.github.com/chris-belcher/eb9abe417d74a7b5f20aabe6bff10de0)

通过生成pre 与 next 节点用于存在性证明的MerkleBlock Message来实现不存在性证明。

python实现代码

```
#不存在性证明基于交易是排序的
def Exclusion_proof(element,Treenode,blocks):
    Value = hashlib.sha256(element.encode()).hexdigest()
    if Value in Treenode[0]:
        print('element exist.')
    else:
        length = len(Treenode[0])
        for i in range(length-1):
            if blocks[i]<element and blocks[i+1]>element:
                print('Pre:',blocks[i])
                Inclusion_Proof(blocks[i],Treenode)
                print('Next:',blocks[i+1])
                Inclusion_Proof(blocks[i+1],Treenode)
                print("Exclusion proof correct.")
            else:
                continue
    return
```

## 代码运行结果展示

![image](https://github.com/1-14/Project5/blob/main/4.png)

可以看到成功生成默克尔树，并成功进行了两个证明
