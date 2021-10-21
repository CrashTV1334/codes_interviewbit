class Solution:
    # @param A : list of integers
    # @param B : integer
    # @return an integer
    def solve(self, A, B):
        i, n, bulb = 0, len(A), 0
        while i < n:   
            flag = False
            j = min(i+B-1, n-1)
            while j>=i-B+1 and j<n and j>0:
                if A[j] ==1:
                    flag = True
                    bulb += 1
                    i = j + B
                    break
                j -= 1
            if not flag:
                return -1
        return bulb